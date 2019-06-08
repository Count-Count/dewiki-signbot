#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Original code by zhuyifei1999 (https://wikitech.wikimedia.org/wiki/User:Zhuyifei1999)
# Heavily modified by Count Count (https://de.wikipedia.org/wiki/Benutzer:Count_Count)
# under the terms of Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# https://creativecommons.org/licenses/by-sa/3.0/

from __future__ import unicode_literals

import os
import re
import time
import random
import signal
import threading
import hashlib
import locale
import pytz

import pywikibot
from pywikibot.comms.eventstreams import site_rc_listener
from pywikibot.diff import PatchManager

#from redis import Redis
#from redisconfig import KEYSIGN


TIMEOUT = 60  # We expect at least one rc entry every minute


class TimeoutError(Exception):
    pass


def on_timeout(signum, frame):
    raise TimeoutError


class Controller():
    def __init__(self):
        self.site = pywikibot.Site(user='CountCountBot')
        self.site.login()  # T153541
        self.timezone = pytz.timezone('Europe/Berlin')
        self.reloadRegex()
        self.reloadOptOut()
        self.useroptin = [] # not implemented
#        self.redis = Redis(host='tools-redis')

    def run(self):
        signal.signal(signal.SIGALRM, on_timeout)
        signal.alarm(TIMEOUT)

        rc = site_rc_listener(self.site)

        for change in rc:
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
                t = BotThread(self.site, change, self)
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

    def checknotify(self, user):
        return False
#        if user.isAnonymous():
#            return False
#        reset = int(time.time()) + 86400
#        key = KEYSIGN + ':'
#        key += hashlib.md5(user.username.encode('utf-8')).hexdigest()
#        p = self.redis.pipeline()
#        p.incr(key)
#        p.expireat(key, reset + 10)
#        return p.execute()[0] >= 3


class BotThread(threading.Thread):
    def __init__(self, site, change, controller):
        threading.Thread.__init__(self)
        self.site = site
        self.change = change
        self.controller = controller

    def changeShouldBeHandled(self):
        self.page = pywikibot.Page(
            self.site, self.change['title'], ns=self.change['namespace'])
        self.output('Handling')

        if self.isPageOptOut(self.page.title(insite=True)):
            self.output('Page %s on opt-out list' % self.page.title(insite=True))
            return False, False, False

        if self.page.title(insite=True).find('/Archiv/') > 0:
            self.output('Suspected archive page')
            return False, False, False

        if self.page.isRedirectPage():
            self.output('Redirect')
            return False, False, False
        if self.page.namespace() == 4:
            # Project pages needs attention (__NEWSECTIONLINK__)
            if not self.isDiscussion(self.page):
                self.output('Not a discussion')
                return False, False, False

        if {'mw-undo', 'mw-rollback'}.intersection(self.getTags()):
            self.output('undo / rollback')
            return False, False, False

        user = pywikibot.User(self.site, self.change['user'])
        if self.isUserOptOut(user.username):
            self.output('%s opted-out' % user.username)
            return False, False, False

        # diff-reading.
        if self.change['type'] == 'new':
            old_text = ''
        else:
            old_text = self.page.getOldVersion(self.change['revision']['old'])

        new_text = self.page.getOldVersion(self.change['revision']['new'])

        if '{{sla' in new_text.lower() \
          or '{{löschen' in new_text.lower() \
          or '{{delete' in new_text.lower():
            self.output('{{sla -- ignored')
            return False, False, False

        diff = PatchManager(old_text.split('\n') if old_text else [],
                            new_text.split('\n'),
                            by_letter=True)
#        diff.print_hunks()

        tosignstr = False
        tosignnum = False

        deleteCount = 0
        replaceCount = 0

        for block in diff.blocks:
            if block[0] < 0:
                continue
            hunk = diff.hunks[block[0]]
            group = hunk.group

            for tag, i1, i2, j1, j2 in group:
                if tag == 'insert':
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
                                return False, False, False

                        excluderegextest = self.matchExcludeRegex(line)
                        if excluderegextest is not None:
                            self.output('Matches %s -- ignored' % excluderegextest)
                            return False, False, False

                        if self.isComment(line):
                            tosignnum = j
                            tosignstr = line
                            if self.isSigned(user, tosignstr):
                                self.output('Signed')
                                return False, False, False
                if tag == 'delete':
                    deleteCount += 1
                if tag == 'replace':
                    replaceCount += 1

        if tosignstr is False:
            self.output('No inserts')
            return False, False, False
        if self.isSigned(user, tosignstr):
            self.output('Signed')
            return False, False, False

        if deleteCount > 0 or replaceCount > 0:
            self.output('Deleted or replaced lines found')
            return False, False, False
        
        # all checks passed
        return True, tosignnum, tosignstr

    def run(self):
        res, tosignnum, tosignstr = self.changeShouldBeHandled()
        if not res:
            return

        if not self.isFreqpage(self.page):
            self.output('Waiting')
            time.sleep(5 * 60)
            pass
            self.output('Woke up')

        user = pywikibot.User(self.site, self.change['user'])

        currenttext = self.page.get(force=True).split('\n')
        if (tosignnum < len(currenttext) and
                currenttext[tosignnum] == tosignstr):
            currenttext[tosignnum] += self.getSignature(tosignstr, user)
            signedLine = currenttext[tosignnum]
        elif currenttext.count(tosignstr) == 1:
            currenttext[currenttext.index(tosignstr)] += \
                self.getSignature(tosignstr, user)
            signedLine = [currenttext.index(tosignstr)]
        else:
            self.output('Line no longer found, probably signed')
            return

        summary = "Bot: Signaturnachtrag für Beitrag von %s: \"%s\"" % (
            self.userlink(user), self.change['comment'])

        self.writeLog(self.page, signedLine, summary, self.change['revision']['new'], user, self.change['comment'], self.change['timestamp'])

        if True:
            if not self.page.title().startswith('Benutzer Diskussion:CountCountBot/'):
                self.output('Would have handled - ignoring.')
                return

        self.userPut(self.page, self.page.get(),
                     '\n'.join(currenttext), comment=summary)

        # self.notify(user) {{subst:Please sign}} -- ignore {{bots}}
        if self.controller.checknotify(user):
            self.output('Notifying %s' % user)
            talk = user.getUserTalkPage()
            if talk.isRedirectPage():
                talk = talk.getRedirectTarget()
            try:
                talktext = talk.get(force=True, get_redirect=True) + '\n\n'
            except pywikibot.NoPage:
                talktext = ''

            talktext += '{{subst:Unterschreiben}}'
            self.userPut(talk, talk.text, talktext,
                         comment='Bot: Hinweisvorlage {{subst:Unterschreiben}} ergänzt',
                         minor=False)

    def output(self, info):
        pywikibot.output('%s: %s' % (self.page, info))

    def getTags(self):
        req = self.site._simple_request(
            action='query',
            prop='revisions',
            titles=self.page,
            rvprop='tags',
            rvstartid=self.change['revision']['new'],
            rvendid=self.change['revision']['new'],
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

    def getSignature(self, tosignstr, user):
        p = ''
        if tosignstr[-1] != ' ':
            p = ' '
        timestamp = self.getSignatureTimestampString(self.change['timestamp'])
        return p + '{{unsigniert|%s|%s}}' % (
            user.username,
            timestamp
        )
    
    def getSignatureTimestampString(self, timestamp):
        return pytz.utc.localize(pywikibot.Timestamp.utcfromtimestamp(timestamp)) \
            .astimezone(self.controller.timezone).strftime('%H:%M, %-d. %B %Y (%Z)')

    def userlink(self, user):
        if user.isAnonymous():
            return '[[Special:Contributions/%s|%s]]' % (
                user.username, user.username)
        else:
            return '[[User:%s|%s]]' % (user.username, user.username)

    def isSigned(self, user, tosignstr):
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

    def isComment(self, line):
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
        if re.match(r'^__[A-Z]+__$', tempstr):
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

    def isFreqpage(self, page):
        # TODO
        return False

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

    def writeLog(self, page, botLine, summary, revision, user, revSummary, revTimestamp):
        logPage = pywikibot.Page(self.site, 'Benutzer:CountCountBot/Log')
        oldText = logPage.text
        text = oldText
        summary = summary.replace('{{', '<nowiki>{{</nowiki>')
        if not text.endswith('\n'):
            text += '\n'
        text += '\n'
        revTimestampString = self.getSignatureTimestampString(revTimestamp)
        text += "=== %s ===\n[https://de.wikipedia.org/w/index.php?title=%s&diff=prev&oldid=%s Unsignierte Bearbeitung] von {{noping|%s}} um %s.<br>\n" % (page.title(as_link=True), page.title(as_url=True), revision, user.username, revTimestampString)
        text += "Generierte Bot-Bearbeitung: ''(%s)''\n<pre>%s</pre>\n\n" % (summary, botLine)
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
#        if self.simulate:
        if True:
            pywikibot.showDiff(oldtext, newtext)
            if 'comment' in kwargs:
                pywikibot.output('Comment: %s' % kwargs['comment'])

#            return

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
