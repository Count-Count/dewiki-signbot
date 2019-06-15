#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Original code by zhuyifei1999 (https://wikitech.wikimedia.org/wiki/User:Zhuyifei1999)
# Heavily modified by Count Count (https://de.wikipedia.org/wiki/Benutzer:Count_Count)
# under the terms of Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# https://creativecommons.org/licenses/by-sa/3.0/

from __future__ import unicode_literals

import datetime
import unittest
from urllib.parse import urlparse, parse_qs
import os
import re
import time
import random
import signal
import threading
import hashlib
import base64
import locale
import pytz

import pywikibot
from pywikibot.comms.eventstreams import site_rc_listener
from pywikibot.diff import PatchManager

from redis import Redis


TIMEOUT = 60  # We expect at least one rc entry every minute


class TimeoutError(Exception):
    pass


def on_timeout(signum, frame):
    raise TimeoutError


class RevisionInfo():
    @classmethod
    def fromRecentChange(cls, change) -> 'RevisionInfo':
        return cls(change['namespace'],
                   change['title'],
                   change['type'],
                   change['bot'],
                   change['comment'],
                   change['user'],
                   change['revision']['old'] if change['type'] == 'edit' else None,
                   change['revision']['new'],
                   change['timestamp']
                   )

    def __init__(self, namespace, title, edittype, bot, comment, user, oldRevision, newRevision, timestamp):
        self.namespace = namespace
        self.title = title
        self.bot = bot
        self.type = edittype  # 'edit' or 'new' or ...
        self.comment = comment
        self.user = user
        self.newRevision = newRevision
        self.oldRevision = oldRevision
        self.timestamp = timestamp


class Controller():
    logEntries = True
    doEdits = True

    def __init__(self):
        self.site = pywikibot.Site(user='CountCountBot')
        self.site.login()  # T153541
        self.reloadRegex()
        self.reloadOptOut()
        self.useroptin = []  # not implemented
        self.botkey = os.environ.get('REDIS_KEY')
        if not self.botkey or '' == self.botkey.strip():
            raise Exception('REDIS_KEY environment variable not set')
        self.redis = Redis(host='tools-redis' if os.name !=
                           'nt' else 'localhost')

    def run(self):
        if os.name != 'nt':
            signal.signal(signal.SIGALRM, on_timeout)
            signal.alarm(TIMEOUT)

        rc = site_rc_listener(self.site)

        for change in rc:
            if os.name != 'nt':
                signal.alarm(TIMEOUT)

            if change['namespace'] == 2 and change['title'] == ('Benutzer:CountCountBot/exclude regex'):
                pywikibot.output('exclude regex page changed')
                threading.Thread(target=self.reloadRegex).start()

            if change['namespace'] == 2 and change['title'] == ('Benutzer:CountCountBot/Opt-Out'):
                pywikibot.output('opt-out page changed')
                threading.Thread(target=self.reloadOptOut).start()

            # Talk page or project page, bot edits excluded
            if (
                (not change['bot']) and
                (change['namespace'] == 4 or change['namespace'] % 2 == 1) and
                (change['type'] in ['edit', 'new']) and
                ('!nosign!' not in change['comment']) and
                (not change['comment'].startswith('Bot: '))
            ):
                t = BotThread(
                    self.site, RevisionInfo.fromRecentChange(change), self)
                t.start()

        pywikibot.log('Main thread exit - THIS SHOULD NOT HAPPEN')
        time.sleep(10)

    def reloadRegex(self):
        pywikibot.output('Reloading exclude regex')
        # We do not directly assign to self.controller.excluderegex right
        # now to avoid issues with multi-threading
        lst = []

        repage = pywikibot.Page(self.site, 'User:CountCountBot/exclude_regex')
        for line in repage.get(force=True).split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                lst.append(re.compile(line, re.I))

        self.excluderegex = lst

    def reloadOptOut(self):
        pywikibot.output('Reloading optout list')
        optoutPage = pywikibot.Page(self.site, 'User:CountCountBot/Opt-Out')
        newuseroptout = set()
        newpageoptout = set()
        for wikilink in pywikibot.link_regex.finditer(
                pywikibot.textlib.removeDisabledParts(optoutPage.get(force=True))):
            if not wikilink.group('title').strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group('title'),
                                      source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            if link.namespace == 2:
                #                pywikibot.output('optout found for user %s' % link.title.strip())
                newuseroptout.add(link.title.strip())
            else:
                #                pywikibot.output('optout found for page %s' % link.ns_title(onsite=self.site).strip())
                newpageoptout.add(link.ns_title(onsite=self.site).strip())
        self.useroptout = newuseroptout
        self.pageoptout = newpageoptout

    def hash(self, str):
        return base64.b64encode(hashlib.sha224(str.encode('utf-8')).digest()).decode('ascii')

    def getKey(self, user):
        return self.hash(self.botkey)+':'+self.hash(self.botkey+':'+user.username)

    def getSetKey(self):
        return self.hash(self.botkey)+':'+self.hash(self.botkey+':'+self.botkey+':set')

    def checknotify(self, user):
        if user.isAnonymous():
            return False
        reset = int(time.time()) + 60*60*24*30
        key = self.getKey(user)
        p = self.redis.pipeline()
        p.incr(key)
        p.expireat(key, reset + 10)
        p.sadd(self.getSetKey(), key)
        limitReached = p.execute()[0] >= 3
        if limitReached:
            p.delete(key)
            p.execute()
            return True

    def clearnotify(self, user):
        if user.isAnonymous():
            return
        key = self.getKey(user)
        p = self.redis.pipeline()
        p.srem(self.getSetKey(), key)
        p.delete(key)
        p.execute()


class ShouldBeHandledResult:
    def __init__(self, tosignnum, tosignstr, isAlreadyTimeSigned, isAlreadyUserSigned):
        self.tosignnum = tosignnum
        self.tosignstr = tosignstr
        self.isAlreadyTimeSigned = isAlreadyTimeSigned
        self.isAlreadyUserSigned = isAlreadyUserSigned


class BotThread(threading.Thread):
    timezone = pytz.timezone('Europe/Berlin')

    def __init__(self, site, revInfo, controller):
        threading.Thread.__init__(self)
        self.site = site
        self.revInfo = revInfo
        self.controller = controller

    def changeShouldBeHandled(self):
        self.page = pywikibot.Page(
            self.site, self.revInfo.title, ns=self.revInfo.namespace)
        self.output('Handling')

        if self.isPageOptOut(self.page.title(insite=True)):
            self.output('Page %s on opt-out list' %
                        self.page.title(insite=True))
            return False, None

        if (self.page.title(insite=True).find('/Archiv/') > 0
            or self.page.title(insite=True).find('/Archiv ') > 0
                or self.page.title(insite=True).endswith('/Archiv')):
            self.output('Suspected archive page')
            return False, None

        if self.page.isRedirectPage():
            self.output('Redirect')
            return False, None
        if self.page.namespace() == 4:
            # Project pages needs attention (__NEWSECTIONLINK__)
            if not self.isDiscussion(self.page):
                self.output('Not a discussion')
                return False, None

        if {'mw-undo', 'mw-rollback'}.intersection(self.getTags()):
            self.output('undo / rollback')
            return False, None

        user = pywikibot.User(self.site, self.revInfo.user)
        if self.isUserOptOut(user.username):
            self.output('%s opted-out' % user.username)
            return False, None

        # diff-reading.
        if self.revInfo.type == 'new':
            old_text = ''
        else:
            old_text = self.page.getOldVersion(self.revInfo.oldRevision)

        new_text = self.page.getOldVersion(self.revInfo.newRevision)

        if '{{sla' in new_text.lower() \
                or '{{löschen' in new_text.lower() \
                or '{{delete' in new_text.lower():
            self.output('{{sla -- ignored')
            return False, None

        new_lines = new_text.split('\n')
        diff = PatchManager(old_text.split('\n') if old_text else [],
                            new_lines,
                            by_letter=True)
#        diff.print_hunks()

        tosignstr = False
        tosignnum = False

        if (len(diff.hunks) > 1):
            self.output('Multiple diff hunks %d' % len(diff.blocks))
            return False, None

        hunk = diff.hunks[0]
        group = hunk.group

        timestamp1 = self.getSignatureTimestampString(self.revInfo.timestamp)
        timestamp2 = self.getSignatureTimestampString(
            self.revInfo.timestamp - 60)

        exactTimeSigned = False
        timeSigned = False
        userSigned = False

        signatureTimestampCount = 0

        for tag, i1, i2, j1, j2 in group:
            if tag == 'insert':
                insertStartLine = j1
                for j in range(j1, j2):
                    line = hunk.b[j]
                    if (
                        self.page == user.getUserTalkPage() or
                        self.page.title().startswith(
                            user.getUserTalkPage().title() + '/')
                    ):
                        if '{{' in line.lower():
                            self.output('User adding templates to their '
                                        'own talk page -- ignored')
                            return False, None

                    excluderegextest = self.matchExcludeRegex(line)
                    if excluderegextest is not None:
                        self.output('Matches %s -- ignored' %
                                    excluderegextest)
                        return False, None

                    if self.isNotExcludedLine(line):
                        tosignnum = j
                        tosignstr = line

                        exactTimeSigned = tosignstr.find(
                            timestamp1) >= 0 or tosignstr.find(timestamp2) >= 0

                        timeSigned = self.hasAnySignatureTimestamp(line)
                        if timeSigned:
                            signatureTimestampCount += 1

                        userSigned = self.isUserSigned(user, tosignstr)
                        if timeSigned and userSigned:
                            self.controller.clearnotify(user)
                            self.output('Signed')
                            return False, None

            if tag == 'delete':
                return False, None
            if tag == 'replace':
                return False, None

        if tosignstr is False:
            self.output('No inserts')
            return False, None

        if signatureTimestampCount > 1:
            self.output('Multiple timestamps found')
            return False, None

        if (self.hasAnySignatureAllowedUserLink(tosignstr)
                and timeSigned
                and not exactTimeSigned):
            self.output('Timestamp and other user link found - likely copied')
            return False, None

        if (not timeSigned and not userSigned and
            self.isPostscriptum(tosignstr) and
                tosignnum > 1):
            checkLineNo = tosignnum - 1
            if new_lines[checkLineNo].strip() == "" and checkLineNo > 0:
                checkLineNo -= 1
            if (self.isUserSigned(user, new_lines[checkLineNo]) and
                    self.hasAnySignatureTimestamp(new_lines[checkLineNo])):
                self.output('Postcriptum found')
                return False, None

        if ((new_lines[insertStartLine].strip().startswith('{{')
             or tosignstr.strip().startswith('{{')) and
                tosignstr.strip().endswith('}}')):
            precedingSignatureOrSectionFound = False
            for i in range(0, insertStartLine):
                if (new_lines[i].strip().startswith('==')):
                    precedingSignatureOrSectionFound = True
                    break
                if self.hasAnySignature(new_lines[i]):
                    precedingSignatureOrSectionFound = True
                    break
            if not precedingSignatureOrSectionFound:
                self.output('Insertion of template at beginning of page')
                return False, None

        # all checks passed
        return True, ShouldBeHandledResult(tosignnum, tosignstr, timeSigned, userSigned)

    def run(self):
        res, shouldBeHandledResult = self.changeShouldBeHandled()
        if not res:
            return

        self.output('Waiting')
        if Controller.doEdits:
            time.sleep(5 * 60)
        self.output('Woke up')

        user = pywikibot.User(self.site, self.revInfo.user)

        currenttext = self.page.get(force=True).split('\n')
        if (shouldBeHandledResult.tosignnum < len(currenttext) and
                currenttext[shouldBeHandledResult.tosignnum] == shouldBeHandledResult.tosignstr):
            currenttext[shouldBeHandledResult.tosignnum] += self.getSignature(
                shouldBeHandledResult.tosignstr, user, shouldBeHandledResult.isAlreadyTimeSigned, shouldBeHandledResult.isAlreadyUserSigned)
            signedLine = currenttext[shouldBeHandledResult.tosignnum]
        elif currenttext.count(shouldBeHandledResult.tosignstr) == 1:
            currenttext[currenttext.index(shouldBeHandledResult.tosignstr)] += self.getSignature(shouldBeHandledResult.tosignstr, user,
                                                                                                 shouldBeHandledResult.isAlreadyTimeSigned, shouldBeHandledResult.isAlreadyUserSigned)
            signedLine = [currenttext.index(shouldBeHandledResult.tosignstr)]
        else:
            self.output('Line no longer found, probably signed')
            return

        summary = "Bot: Signaturnachtrag für Beitrag von %s: \"%s\"" % (
            self.userlink(user), self.revInfo.comment) + self.getTestLink()

#        if self.page.title().startswith('Benutzer Diskussion:CountCountBot/'):
        if Controller.doEdits:
            self.userPut(self.page, self.page.get(),
                         '\n'.join(currenttext), comment=summary)

        notify = self.controller.checknotify(user)
        if notify:
            self.output('Notifying %s' % user)
            talk = user.getUserTalkPage()
            if talk.isRedirectPage():
                talk = talk.getRedirectTarget()
            try:
                talktext = talk.get(force=True, get_redirect=True) + '\n\n'
            except pywikibot.NoPage:
                talktext = ''

            talktext += '{{subst:Unterschreiben}}'
#            if self.page.title().startswith('Benutzer Diskussion:CountCountBot/'):
            if Controller.doEdits:
                self.userPut(talk, talk.text, talktext,
                             comment='Bot: Hinweis zum [[Hilfe:Signatur|Unterschreiben von Diskussionbeiträgen]] ergänzt' + self.getTestLink(
                             ),
                             minor=False)

        if Controller.logEntries:
            self.writeLog(self.page, signedLine, summary, self.revInfo.newRevision,
                          user, self.revInfo.comment, self.revInfo.timestamp, notify)

    def isPostscriptum(self, line):
        return re.match(r'^(:+\s*)?(PS|P\. ?S\.|Nachtrag|Postscriptum)\s*\S', line, re.I) is not None

    def output(self, info):
        pywikibot.output('%s: %s' % (self.page, info))

    def getTags(self):
        req = self.site._simple_request(
            action='query',
            prop='revisions',
            titles=self.page,
            rvprop='tags',
            rvstartid=self.revInfo.newRevision,
            rvendid=self.revInfo.newRevision,
            rvlimit=1
        )
        try:
            res = req.submit()
        except Exception as e:
            pywikibot.exception(e)
            return []
        else:
            try:
                p = res['query']['pages']
                r = p[list(p.keys())[0]]['revisions']
                return r[0]['tags']
            except KeyError:
                return []

    def getSignature(self, tosignstr, user, isAlreadyTimeSigned, isAlreadyUserSigned):
        p = ''
        if tosignstr[-1] != ' ':
            p = ' '
        timestamp = self.getSignatureTimestampString(self.revInfo.timestamp)
        if isAlreadyTimeSigned:
            altText = "|ALT=unvollständig"
            timeInfo = ''
        elif isAlreadyUserSigned:
            altText = "|ALT=ohne (gültigen) Zeitstempel"
            timeInfo = '|' + timestamp
        else:
            altText = ''
            timeInfo = '|' + timestamp
            pass

        return p + '{{unsigniert|%s%s%s}}' % (
            user.username,
            timeInfo,
            altText
        )

    def getTestLink(self):
        return ' (Testbetrieb ohne Botflag)'

    @staticmethod
    def getSignatureTimestampString(timestamp):
        if os.name == 'nt':
            time = pytz.utc.localize(pywikibot.Timestamp.utcfromtimestamp(timestamp)) \
                .astimezone(BotThread.timezone)
            return time.strftime('%H:%M, ')+time.strftime('%e').replace(' ', '')+time.strftime('. %b. %Y (%Z)')
        else:
            return pytz.utc.localize(pywikibot.Timestamp.utcfromtimestamp(timestamp)) \
                .astimezone(BotThread.timezone).strftime('%H:%M, %-d. %b. %Y (%Z)')

    def userlink(self, user):
        if user.isAnonymous():
            return '[[Special:Contributions/%s|%s]]' % (
                user.username, user.username)
        else:
            return '[[User:%s|%s]]' % (user.username, user.username)

    def isUserSigned(self, user, tosignstr):
        for wikilink in pywikibot.link_regex.finditer(
                pywikibot.textlib.removeDisabledParts(tosignstr)):
            if not wikilink.group('title').strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group('title'),
                                      source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
#            if link.site != self.site: continue
            if user.isAnonymous():
                if link.namespace != -1:
                    continue
                if link.title != 'Beiträge/' + user.username:
                    continue
            else:
                if link.namespace == -1 and link.title == 'Beiträge/' + user.username:
                    return True
                if link.namespace not in [2, 3]:
                    continue
                if link.title != user.username:
                    continue
            return True

        return False

    def hasAnySignature(self, text):
        return self.hasAnySignatureAllowedUserLink(text) and self.hasAnySignatureAllowedUserLink()

    def hasAnySignatureAllowedUserLink(self, text):
        for wikilink in pywikibot.link_regex.finditer(text):
            if not wikilink.group('title').strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group('title'),
                                      source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            if link.namespace in [2, 3] and link.title.find('/') == -1:
                return True
            if link.namespace == -1 and link.title.startswith('Beiträge/'):
                return True
        return False

    @staticmethod
    def hasAnySignatureTimestamp(line):
        return re.search(r'[0-9]{2}:[0-9]{2}, [123]?[0-9]\. (?:Jan\.|Feb\.|Mär\.|Apr\.|Mai|Jun\.|Jul\.|Aug\.|Sep\.|Okt\.|Nov\.|Dez\.) 2[0-9]{3} \(CES?T\)', line) is not None

    def isNotExcludedLine(self, line):
        # remove non-functional parts and categories
        tempstr = re.sub(r'\[\[[Kk]ategorie:[^\]]+\]\]', '',
                         pywikibot.textlib.removeDisabledParts(line)).strip()
        # not empty
        if not tempstr:
            return False
        # not heading
        if tempstr.startswith('=') and tempstr.endswith('='):
            return False
        # not table/template
        if (
            tempstr.startswith('!') or
            tempstr.startswith('|') or
            tempstr.startswith('{|') or
            tempstr.endswith('|')
        ):
            return False
        # not horzontal line
        if tempstr.startswith('----'):
            return False
        # not magic words
        if re.match(u'^__[A-ZÄÖÜ_]+__$', tempstr):
            return False

        return True

    def isUserOptOut(self, user):
        # Check for opt-in {{YesAutosign}} -> False
        if user in self.controller.useroptin:
            return False
        # Check for opt-out {{NoAutosign}} -> True
        if user in self.controller.useroptout:
            return True
        # Check for 800 user edits -> False
        # -> True
#        return user.editCount() > 800

    def isPageOptOut(self, page):
        #        self.output("Checking opt-out for %s" % page)
        #        self.output("Page opt-out list: %s" % str(self.controller.pageoptout))
        return page in self.controller.pageoptout

    def isDiscussion(self, page):
        # TODO: sandbox
        # TODO: opt-in

        # __NEWSECTIONLINK__ -> True
        if 'newsectionlink' in self.page.properties():
            return True

        if page.title().startswith('Wikipedia:Löschkandidaten/'):
            return True

        return False

    def matchExcludeRegex(self, line):
        line = line.replace('_', ' ')
        for regex in self.controller.excluderegex:
            reobj = regex.search(line)
            if reobj is not None:
                return reobj.group(0)
        return None

    def writeLog(self, page, botLine, summary, revision, user, revSummary, revTimestamp, notified):
        logPage = pywikibot.Page(self.site, 'Benutzer:CountCountBot/Log')
        oldText = logPage.text
        text = oldText
        summary = summary.replace('{{', '<nowiki>{{</nowiki>')
        if not text.endswith('\n'):
            text += '\n'
        text += '\n'
        notifyString = ' (benachrichtigt)' if notified else ''
        revTimestampString = self.getSignatureTimestampString(revTimestamp)
        text += "=== %s ===\n[https://de.wikipedia.org/w/index.php?title=%s&diff=prev&oldid=%s Unsignierte Bearbeitung] von {{noping|%s}}%s um %s.<br>\n" % (
            page.title(as_link=True), page.title(as_url=True), revision, user.username, notifyString, revTimestampString)
        text += "Generierte Bot-Bearbeitung: ''(%s)''\n<pre>%s</pre>\n\n" % (
            summary, botLine)
        logPage.text = text
        logPage.save(summary='Neuer Log-Eintrag.')

    def userPut(self, page, oldtext, newtext, **kwargs):
        if oldtext == newtext:
            pywikibot.output('No changes were needed on %s'
                             % page.title(asLink=True))
            return
#        elif self.controller.total <= 0:
#            raise RuntimeError('Maxium edits reached!')
        else:
            # self.controller.total -= 1
            pass

        pywikibot.output('\n\n>>> \03{lightpurple}%s\03{default} <<<'
                         % page.title(asLink=True))
        if True:
            pywikibot.showDiff(oldtext, newtext)
            if 'comment' in kwargs:
                pywikibot.output('Comment: %s' % kwargs['comment'])

        page.text = newtext
        try:
            page.save(**kwargs)
            pass
        except pywikibot.Error as e:
            pywikibot.output('Failed to save %s: %r: %s' % (
                page.title(asLink=True), e, e))
            self.controller.total += 1


def main():
    locale.setlocale(locale.LC_ALL, 'de_DE.utf8')
    pywikibot.handle_args()
    Controller().run()


# ----------------------------------------------------


class TestSigning(unittest.TestCase):

    def setUp(self):
        self.controller = Controller()

    def tearDown(self):
        pywikibot.stopme()

    def getRevisionInfo(self, pageUrl: str) -> RevisionInfo:
        re.compile('line', re.I)
        queryVars = parse_qs(urlparse(pageUrl).query)
        title = queryVars['title'][0]
        revId = int(queryVars['oldid'][0])
        page = pywikibot.Page(self.controller.site, title)
        if not page.exists():
            raise Exception("%s - page not found" % title)
        self.assertTrue(page.exists())
        self.controller.site.loadrevisions(page, startid=revId, total=1)
        newRevision = page._revisions[revId]
        epoch = datetime.datetime.utcfromtimestamp(0)
        oldRevId = newRevision.parent_id
        return RevisionInfo(page.namespace(), page.title(), "new" if oldRevId == 0 else "edit", False, newRevision.comment, newRevision.user, oldRevId, revId, (newRevision.timestamp - epoch).total_seconds())

    def checkNeedsToBeFullySigned(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        self.assertTrue(
            res, "Should need full signing but not recognized as unsigned: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyTimeSigned,
                         "Should not be timestamp signed but is: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyUserSigned,
                         "Should not be user signed but is: %s" % pageUrl)

    def checkNeedsUserOnlySigning(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        self.assertTrue(
            res, "Should need user signing but not recognized as unsigned: %s" % pageUrl)
        self.assertTrue(shouldBeHandledResult.isAlreadyTimeSigned,
                        "Should be timestamp signed but is not: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyUserSigned,
                         "Should not be user signed but is: %s" % pageUrl)

    def checkNeedsTimestampOnlySigning(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        self.assertTrue(
            res, "Should need timestamp signing but not recognized as unsigned: %s" % pageUrl)
        self.assertTrue(shouldBeHandledResult.isAlreadyUserSigned,
                        "Should be user signed bot is not: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyTimeSigned,
                         "Should not be timestamp signed but is: %s" % pageUrl)

    def checkDoesNotNeedToBeSigned(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, _) = bt.changeShouldBeHandled()
        self.assertFalse(res)

#    @unittest.skip('disabled')
    def test_needToBeFullySigned(self):
        self.checkNeedsToBeFullySigned(
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion%3AAgathenon&diff=prev&oldid=189352195')  # _ in special directive
        pass

    def test_doNotNeedToBeSigned(self):
        self.checkDoesNotNeedToBeSigned(
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:146.185.69.133&diff=prev&oldid=189565765&diffmode=source')  # template at the beginning
        self.checkDoesNotNeedToBeSigned(
            'https://de.wikipedia.org/w/index.php?title=Diskussion%3APostgender&diff=prev&oldid=189397879')  # _ in special directive
        self.checkDoesNotNeedToBeSigned(
            'https://de.wikipedia.org/w/index.php?title=Wikipedia%3AVandalismusmeldung&diff=prev&oldid=189343072')  # moved text
        self.checkDoesNotNeedToBeSigned(
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:L%C3%B6schkandidaten/11._Juni_2019&diff=prev&oldid=189460775&diffmode=source')  # Postscriptum
        self.checkDoesNotNeedToBeSigned(
            'https://de.wikipedia.org/w/index.php?title=Wikipedia_Diskussion:Wiki_Loves_Earth_2019/Deutschland/Organisation&diff=prev&oldid=189464146&diffmode=source')  # Postscriptum

#    @unittest.skip('disabled')
    def test_needsUserOnlySigning(self):
        self.checkNeedsUserOnlySigning(
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:L%C3%B6schkandidaten/5._Juni_2019&diff=prev&oldid=189333235&diffmode=source')

#    @unittest.skip('disabled')
    def test_allNeedToBeFullySigned(self):
        text = pywikibot.Page(
            self.controller.site, 'Benutzer:CountCountBot/Testcases/Beiträge die komplett nachsigniert werden dürfen').get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+', re.I).findall(text)
        for match in matches:
            self.checkNeedsToBeFullySigned(match)

#    @unittest.skip('disabled')
    def test_allDoNotNeedToBeSigned(self):
        text = pywikibot.Page(
            self.controller.site, 'Benutzer:CountCountBot/Testcases/Beiträge die nicht nachsigniert werden dürfen').get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+', re.I).findall(text)
        for match in matches:
            self.checkDoesNotNeedToBeSigned(match)

#    @unittest.skip('disabled')
    def test_allNeedUserOnlySigning(self):
        text = pywikibot.Page(
            self.controller.site, 'Benutzer:CountCountBot/Testcases/Beiträge die als ohne Benutzerinformation nachsigniert werden dürfen').get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+', re.I).findall(text)
        for match in matches:
            self.checkNeedsUserOnlySigning(match)

#    @unittest.skip('disabled')
    def test_allNeedTimestampOnlySigning(self):
        text = pywikibot.Page(
            self.controller.site, 'Benutzer:CountCountBot/Testcases/Beiträge die als ohne Zeitstempel nachsigniert werden dürfen').get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+', re.I).findall(text)
        for match in matches:
            self.checkNeedsTimestampOnlySigning(match)

#    @unittest.skip('disabled')
    def test_timestampMatching(self):
        date = datetime.datetime.now()
        d = datetime.timedelta(days=1)
        for d in range(1, 1000):
            s = BotThread.getSignatureTimestampString(date.timestamp())
            self.assertTrue(BotThread.hasAnySignatureTimestamp(
                s), "Timestamp does not match regex: %s" % s)


# ----------------------------------------------------


if __name__ == '__main__':
    try:
        main()
#        unittest.main()
    finally:
        pywikibot.stopme()
