#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) Count Count, 2019
#
# Original code by zhuyifei1999
# (https://wikitech.wikimedia.org/wiki/User:Zhuyifei1999)
# Heavily modified by Count Count
# (https://de.wikipedia.org/wiki/Benutzer:Count_Count)
# Distributed under the terms of
# Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# https://creativecommons.org/licenses/by-sa/3.0/

import datetime
from datetime import datetime
from datetime import timedelta
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
import traceback
import gc

import pywikibot
from pywikibot.bot import SingleSiteBot, ExistingPageBot, NoRedirectPageBot
from pywikibot.comms.eventstreams import site_rc_listener
from pywikibot.diff import PatchManager
from pywikibot.pagegenerators import LiveRCPageGenerator

from redis import Redis

# https://gerrit.wikimedia.org/r/#/c/pywikibot/core/+/525179/
def monkey_patch(site):
    from pywikibot.site import PageInUse

    def lock_page(self, page, block=True):
        """
        Lock page for writing. Must be called before writing any page.
        We don't want different threads trying to write to the same page
        at the same time, even to different sections.
        @param page: the page to be locked
        @type page: pywikibot.Page
        @param block: if true, wait until the page is available to be locked;
            otherwise, raise an exception if page can't be locked
        """
        title = page.title(with_section=False)

        self._pagemutex.acquire()
        try:
            while title in self._locked_pages:
                if not block:
                    raise PageInUse(title)

                # The mutex must be released so that page can be unlocked
                self._pagemutex.release()
                time.sleep(.25)
                self._pagemutex.acquire()

            self._locked_pages.append(title)
        finally:
            # time.sleep may raise an exception from signal handler (eg:
            # KeyboardInterrupt) while the lock is released, and there is no
            # reason to acquire the lock again given that our caller will
            # receive the exception. The state of the lock is therefore
            # undefined at the point of this finally block.
            try:
                self._pagemutex.release()
            except RuntimeError:
                pass

    site.__class__.lock_page = lock_page

TIMEOUT = 600  # We expect at least one rc entry every 10 minutes


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


class Controller(SingleSiteBot, ExistingPageBot, NoRedirectPageBot):
    """The Signbot class."""

    logEntries = False
    doEdits = True
    doNotify = True

    def __init__(self, **kwargs):
        site = pywikibot.Site(user='CountCountBot')
        monkey_patch(site)
        super(Controller, self).__init__(site=site, **kwargs)
        self.reloadRegex()
        self.reloadOptOut()
        self.reloadOptIn()
        self.botkey = os.environ.get('REDIS_KEY')
        if not self.botkey or '' == self.botkey.strip():
            raise Exception('REDIS_KEY environment variable not set')
        self.redis = Redis(host='tools-redis'
                           if os.name != 'nt' else 'localhost')
        self.generator = LiveRCPageGenerator(self.site)
        self.activeWorkerThreads = 0

    def setup(self):
        """Setup the bot."""
        if os.name != 'nt':
            signal.signal(signal.SIGALRM, on_timeout)
            signal.alarm(TIMEOUT)

        self.startCount = 0
        self.startTime = datetime.now()

    def skip_page(self, page):
        """Skip special/media pages"""
        if page.namespace().id < 0:
            pywikibot.warning(
                'Page {page} is a special or media page.'
                .format(page=page))
            return True
        return super().skip_page(page)

    def treat(self, page):
        """Process a single Page object from stream."""
        change = page._rcinfo

        if os.name != 'nt':
            signal.alarm(TIMEOUT)

        if change['namespace'] == 2 and change['title'] == ('Benutzer:CountCountBot/exclude regex'):
            pywikibot.output('exclude regex page changed')
            threading.Thread(target=self.reloadRegex).start()

        elif change['namespace'] == 2 and change['title'] == ('Benutzer:CountCountBot/Opt-Out'):
            pywikibot.output('opt-out page changed')
            threading.Thread(target=self.reloadOptOut).start()

        elif change['namespace'] == 2 and change['title'] == ('Benutzer:CountCountBot/Opt-In'):
            pywikibot.output('opt-in page changed')
            threading.Thread(target=self.reloadOptIn).start()

        # Talk page or project page, bot edits excluded
        elif (
            (not change['bot']) and
            (change['namespace'] == 4
                or change['namespace'] % 2 == 1
                or change['title'] in self.pageoptin) and
            (change['type'] in ['edit', 'new']) and
            ('nosig!' not in change['comment']) and
            (not change['comment'].startswith('Bot: '))
        ):
            t = BotThread(
                self.site, RevisionInfo.fromRecentChange(change), self)
            self.activeWorkerThreads += 1
            t.start()
            self.startCount += 1
            if self.startCount % 5 == 0:
                pywikibot.output('Active threads: %d' %
                                 self.activeWorkerThreads)

    def teardown(self):
        """Bot has finished due to unknown reason."""
        if self._generator_completed:
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
        lst.append(re.compile(r'{{(?:Vorlage:)?nobots\|unsigned}}', re.I))
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

    def reloadOptIn(self):
        pywikibot.output('Reloading optin list')
        optinPage = pywikibot.Page(self.site, 'User:CountCountBot/Opt-In')
        newpageoptin = set()
        for wikilink in pywikibot.link_regex.finditer(
                pywikibot.textlib.removeDisabledParts(optinPage.get(force=True))):
            if not wikilink.group('title').strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group('title'),
                                      source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            if link.namespace != 0:
                newpageoptin.add(link.ns_title(onsite=self.site).strip())
        self.pageoptin = newpageoptin

    def hash(self, str):
        return base64.b64encode(hashlib.sha224(str.encode('utf-8')).digest()).decode('ascii')

    def getKey(self, user):
        return self.hash(self.botkey)+':'+self.hash(self.botkey+':'+user.username)

    def isExperiencedUser(self, user):
        return not user.isAnonymous() and user.editCount() > 500

    def checknotify(self, user):
        if not Controller.doNotify:
            return False
        if user.isAnonymous():
            return False
        if self.isExperiencedUser(user):
            return False
        reset = int(time.time()) + 60*60*24*30
        key = self.getKey(user)
        p = self.redis.pipeline()
        p.incr(key)
        p.expireat(key, reset + 10)
        limitReached = p.execute()[0] >= 3
        if limitReached:
            p.delete(key)
            p.execute()
            return True

    def clearnotify(self, user):
        if not Controller.doNotify:
            return False
        if user.isAnonymous():
            return
        key = self.getKey(user)
        p = self.redis.pipeline()
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
        self.page = None

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

        if (self.page.title(insite=True).startswith('Portal Diskussion:')
                and (self.page.title(insite=True).endswith('/Artikel des Monats')
                     or self.page.title(insite=True).endswith('/Neue Artikel'))):
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

        if (self.page.namespace() == pywikibot.site.Namespace.USER_TALK 
                and self.page.title(with_ns=False) == user.username
                and self.controller.isExperiencedUser(user)):
            self.output('Experienced user %s edited own talk page' % user.username)
            return False, None

        # diff-reading.
        if self.revInfo.type == 'new':
            old_text = ''
        else:
            old_text = self.page.getOldVersion(self.revInfo.oldRevision)

        new_text = self.page.getOldVersion(self.revInfo.newRevision)

        if ('{{sla' in new_text.lower()
                or '{{löschen' in new_text.lower()
                or '{{delete' in new_text.lower()):
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

                        timeSigned = timeSigned or self.hasAnySignatureTimestamp(line)
                        if timeSigned:
                            signatureTimestampCount += 1

                        userSigned = userSigned or self.isUserSigned(user, tosignstr)
                        if timeSigned and userSigned:
                            self.controller.clearnotify(user)
                            self.output('Already signed')
                            return False, None

            if tag == 'delete':
                self.output('Line deletion found')
                return False, None
            if tag == 'replace':
                self.output('Line replacement found')
                return False, None

        if tosignstr is False:
            self.output('No inserts')
            return False, None

        if signatureTimestampCount > 1:
            self.output('Multiple timestamps found')
            return False, None

        if (self.hasAnySignatureAllowedUserLink(tosignstr)
                and timeSigned):
            if not exactTimeSigned:
                self.output(
                    'Timestamp and other user link found - likely copied')
                return False, None
            elif self.controller.isExperiencedUser(user):
                self.output(
                    'Other user link found with exact timestamp - likely copied')
                return False, None

        if not timeSigned and not userSigned:
            if self.isAlreadySignedInFollowingLines(user, new_lines, tosignnum):
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

        if not timeSigned:
            precedingSignatureOrSectionFound = False
            for i in range(0, insertStartLine):
                if (new_lines[i].strip().startswith('==')):
                    precedingSignatureOrSectionFound = True
                    break
                if self.hasAnySignature(new_lines[i]):
                    precedingSignatureOrSectionFound = True
                    break
            followingSignatureOrSectionFound = False
            for i in range(tosignnum + 1, len(new_lines)):
                if (new_lines[i].strip().startswith('==')):
                    followingSignatureOrSectionFound = True
                    break
                if self.hasAnySignature(new_lines[i]):
                    followingSignatureOrSectionFound = True
                    break
            if not precedingSignatureOrSectionFound:
                if ((new_lines[insertStartLine].strip().startswith('{{')
                     or tosignstr.strip().startswith('{{')) and
                        tosignstr.strip().endswith('}}')):
                    self.output('Insertion of template at beginning of page')
                    return False, None
                if followingSignatureOrSectionFound and self.controller.isExperiencedUser(user):
                    self.output(
                        'Insertion by experienced user at the beginning of talk page before any sections or signatures')
                    return False, None

        if self.hasApplicableNobotsTemplate(new_lines, insertStartLine):
            return False, None

        # all checks passed
        return True, ShouldBeHandledResult(tosignnum, tosignstr, timeSigned, userSigned)

    def hasApplicableNobotsTemplate(self, new_lines, insertStartLine):
        for line in new_lines:
            if re.search(r'{{(?:Vorlage:)?nobots\|unsigned}}', line, re.I):
                self.output('Global {{nobots|unsigned}} found')
                return True
            elif line.startswith('='):
                break

        secIndex = 1000
        if insertStartLine > 1:
            for i in range(insertStartLine - 2, -1, -1):
                line = new_lines[i].strip()
                match = re.match(r'^(=+).*[^=](=+)$', line)
                if match and len(match.group(1)) == len(match.group(2)) and len(match.group(1)) < secIndex:
                    # skip empty lines
                    checkLineForBotsDirectiveIndex = i + 1
                    while checkLineForBotsDirectiveIndex < insertStartLine - 1:
                        if new_lines[checkLineForBotsDirectiveIndex].strip():
                            break
                        checkLineForBotsDirectiveIndex += 1
                    lineAfterSectionStart = new_lines[checkLineForBotsDirectiveIndex].strip(
                    )
                    if re.search(r'{{(?:Vorlage:)?nobots\|unsigned}}', lineAfterSectionStart, re.I):
                        self.output(
                            '{{nobots|unsigned}} found for section %s' % line)
                        return True
                    secIndex = len(match.group(1))
        return False

    def isAlreadySignedInFollowingLines(self, user, new_lines, tosignnum):
        for lineNo in range(tosignnum + 1, len(new_lines)):
            line = new_lines[lineNo].strip()
            if (self.isUserSigned(user, line) and
                    self.hasAnySignatureTimestamp(line)):
                self.output('Found user\'s signature in lines after edit')
                return True
            elif self.hasUnsignedTemplateForUser(user, line):
                self.output(
                    'Found signed template for user in lines after edit')
                return True
            elif line.startswith('='):
                # new section found
                return False
            elif self.hasAnySignatureTimestamp(line):
                # other signature found
                return False
        return False

    def continueSigningGetLineIndex(self, user, shouldBeHandledResult, currenttext):
        if (shouldBeHandledResult.tosignnum < len(currenttext) and
                currenttext[shouldBeHandledResult.tosignnum] == shouldBeHandledResult.tosignstr):
            tosignindex = shouldBeHandledResult.tosignnum
        elif currenttext.count(shouldBeHandledResult.tosignstr) == 1:
            # line not at same position but just one line with same text found, assuming that it is the line to be signed
            tosignindex = currenttext.index(shouldBeHandledResult.tosignstr)
        else:
            self.output('Line no longer found, probably signed')
            return -1
        if self.isAlreadySignedInFollowingLines(user, currenttext, tosignindex):
            return -1
        if self.hasApplicableNobotsTemplate(currenttext, tosignindex):
            return -1
        return tosignindex

    def run(self):
        try:
            self.run0()
            self.controller.activeWorkerThreads -= 1
        except Exception as e:
            self.controller.activeWorkerThreads -= 1
            self.error(traceback.format_exc())

    def run0(self):
        res, shouldBeHandledResult = self.changeShouldBeHandled()
        if not res:
            return

        self.output('Waiting')
        if Controller.doEdits:
            time.sleep(5 * 60)
        self.output('Woke up')

        user = pywikibot.User(self.site, self.revInfo.user)

        currenttext = self.page.get(force=True).split('\n')
        tosignindex = self.continueSigningGetLineIndex(
            user, shouldBeHandledResult, currenttext)
        if tosignindex < 0:
            return
        currenttext[tosignindex] += self.getSignature(
            shouldBeHandledResult.tosignstr, user, shouldBeHandledResult.isAlreadyTimeSigned, shouldBeHandledResult.isAlreadyUserSigned)
        signedLine = currenttext[tosignindex]

        self.output('Signing')

        originalSummary = ": \"%s\"" % self.revInfo.comment if len(
            self.revInfo.comment.strip()) > 0 else ''

        summary = "Bot: Signaturnachtrag für Beitrag von %s%s" % (
            self.userlink(user), originalSummary)

#        if self.page.title().startswith('Benutzer Diskussion:CountCountBot/'):
        if Controller.doEdits:
            self.userPut(self.page, self.page.get(),
                         '\n'.join(currenttext), comment=summary, botflag=False)

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
                             comment='Bot: Hinweis zum [[Hilfe:Signatur|Unterschreiben von Diskussionbeiträgen]] ergänzt',
                             minor=False,
                             botflag=False)

        if (Controller.logEntries and self.controller.isExperiencedUser(user) and not shouldBeHandledResult.isAlreadyUserSigned):
            self.writeLog(self.page, signedLine, summary, self.revInfo.newRevision,
                          user, self.revInfo.comment, self.revInfo.timestamp, notify)

    def isPostscriptum(self, line):
        return re.match(r'^(:+\s*)?(PS|P\. ?S\.|Nachtrag|Postscriptum)\s*\S', line, re.I) is not None

    def output(self, info):
        pywikibot.output('%s: %s' % (self.page, info))

    def error(self, info):
        pywikibot.error('%s: %s' % (self.page, info))

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

    @staticmethod
    def getSignatureTimestampString(timestamp):
        time = pytz.utc.localize(pywikibot.Timestamp.utcfromtimestamp(timestamp)) \
            .astimezone(BotThread.timezone)
        abbrevDot = '' if time.month == 5 else '.'  # no abbrev dot for Mai
        if os.name == 'nt':
            return (time.strftime('%H:%M, ')+time.strftime('%e').replace(' ', '')+time.strftime('. %b'+abbrevDot+' %Y (%Z)')).replace('Mrz', 'Mär')
        else:
            return time.strftime('%H:%M, %-d. %b'+abbrevDot+' %Y (%Z)')

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
        return self.hasAnySignatureAllowedUserLink(text) and self.hasAnySignatureTimestamp(text)

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
            # Certain Bot signatures lead to subpages sometimes
            if link.namespace in [2, 3] and link.title.find('/') == -1:
                return True
            if link.namespace == -1 and link.title.startswith('Beiträge/'):
                return True
        return False

    @staticmethod
    def hasAnySignatureTimestamp(line):
        return re.search(r'[0-9]{2}:[0-9]{2}, [123]?[0-9]\. (?:Jan\.|Feb\.|Mär\.|Apr\.|Mai|Jun\.|Jul\.|Aug\.|Sep\.|Okt\.|Nov\.|Dez\.) 2[0-9]{3} \((CES?T|MES?Z)\)', line) is not None

    @staticmethod
    def hasUnsignedTemplateForUser(user, line):
        match = re.search(
            r'{{(?:Vorlage:)?(?:unsigniert|unsigned)\|([^|}]+)', line)
        if match:
            if user.isAnonymous():
                return match.group(1).strip().lower() == user.username.lower()
            else:
                return match.group(1).strip() == user.username

    def isNotExcludedLine(self, line):
        # remove non-functional parts and categories
        tempstr = re.sub(r'\[\[[Kk]ategorie:[^\]]+\]\]', '',
                         pywikibot.textlib.removeDisabledParts(line)).strip()
        tempstr = re.sub(r'<br\s*/>', '', tempstr)
        tempstr = re.sub(
            r'\[\[(Datei|File):([^\]\[]|(\[\[[^\]]+\]\]))+\]\]', '', tempstr, 0, re.I)
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

        # __NEWSECTIONLINK__ -> True
        if 'newsectionlink' in self.page.properties():
            return True

        if page.title() in self.controller.pageoptin:
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
        logPage.save(summary='Neuer Log-Eintrag.', botflag=False)

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


if __name__ == '__main__':
    try:
        main()
    finally:
        pywikibot.stopme()
