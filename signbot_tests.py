#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Test suite for signbot."""
#
# (C) Count Count, 2019
# (https://de.wikipedia.org/wiki/Benutzer:Count_Count)
#
# Distributes under the terms of
# Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# https://creativecommons.org/licenses/by-sa/3.0/
import datetime
import locale
import re
import unittest
from urllib.parse import parse_qs, urlparse

import pywikibot

from signbot import BotThread, Controller, RevisionInfo


class TestSigning(unittest.TestCase):

    def setUp(self):
        locale.setlocale(locale.LC_ALL, 'de_DE.utf8')
        super(TestSigning, self).setUp()
        self.controller = Controller()

    def tearDown(self):
        pywikibot.stopme()
        super(TestSigning, self).tearDown()

    def getRevisionInfo(self, pageUrl: str) -> RevisionInfo:
        re.compile('line', re.I)
        queryVars = parse_qs(urlparse(pageUrl).query)
        title = queryVars['title'][0]
        revId = int(queryVars['oldid'][0])
        page = pywikibot.Page(self.controller.site, title)
        if not page.exists():
            raise Exception("%s - page not found" % title)
        self.assertTrue(page.exists())
        self.controller.site.loadrevisions(
            page, startid=revId, rvdir=True, total=100)

        found = False
        cutoffTime = page._revisions[revId].timestamp + \
            datetime.timedelta(seconds=5*60)
        lastRevInWindow = revId
        for id in sorted(page._revisions):
            if id == revId:
                found = True
            elif found:
                if page._revisions[id].timestamp < cutoffTime:
                    lastRevInWindow = id
        newRevision = page._revisions[revId]
        epoch = datetime.datetime.utcfromtimestamp(0)
        oldRevId = newRevision.parent_id
        linesAfterDelay = page.getOldVersion(lastRevInWindow).split('\n')
        return (linesAfterDelay, RevisionInfo(
            page.namespace(), page.title(), 'new' if oldRevId == 0 else 'edit',
            False, newRevision.comment, newRevision.user, oldRevId, revId,
            (newRevision.timestamp - epoch).total_seconds()))

    def shouldBeHandled(self, pageUrl):
        (linesAfterDelay, rev) = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        user = pywikibot.User(self.controller.site, rev.user)
        if res:
            if bt.continueSigningGetLineIndex(user, shouldBeHandledResult, linesAfterDelay) < 0:
                return (False, None)
        return (res, shouldBeHandledResult)

    def checkNeedsToBeFullySigned(self, pageUrl):
        (res, shouldBeHandledResult) = self.shouldBeHandled(pageUrl)
        self.assertTrue(
            res,
            'Should need full signing but not recognized as unsigned: {}'
            .format(pageUrl))
        self.assertFalse(shouldBeHandledResult.isAlreadyTimeSigned,
                         "Should not be timestamp signed but is: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyUserSigned,
                         "Should not be user signed but is: %s" % pageUrl)

    def checkNeedsUserOnlySigning(self, pageUrl):
        (res, shouldBeHandledResult) = self.shouldBeHandled(pageUrl)
        self.assertTrue(
            res,
            'Should need user signing but not recognized as unsigned: {}'
            .format(pageUrl))
        self.assertTrue(shouldBeHandledResult.isAlreadyTimeSigned,
                        "Should be timestamp signed but is not: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyUserSigned,
                         "Should not be user signed but is: %s" % pageUrl)

    def checkNeedsTimestampOnlySigning(self, pageUrl):
        (res, shouldBeHandledResult) = self.shouldBeHandled(pageUrl)
        self.assertTrue(
            res,
            'Should need timestamp signing but not recognized as unsigned: {}'
            .format(pageUrl))
        self.assertTrue(shouldBeHandledResult.isAlreadyUserSigned,
                        "Should be user signed bot is not: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyTimeSigned,
                         "Should not be timestamp signed but is: %s" % pageUrl)

    def checkDoesNotNeedToBeSigned(self, pageUrl):
        (res, shouldBeHandledResult) = self.shouldBeHandled(pageUrl)
        self.assertFalse(res,
                         "Should not need signing by bot but does: %s" % pageUrl)

#    @unittest.skip('disabled')
    def test_needToBeFullySigned(self):
        #        self.checkNeedsToBeFullySigned(
        #            # ...
        #            'https://de.wikipedia.org/w/index.php?title=Wikipedia:Administratoren/Notizen&diff=prev&oldid=190236331&diffmode=source')
        self.checkNeedsToBeFullySigned(
            # _ in special directive
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion%3AAgathenon&diff=prev&oldid=189352195')

#    @unittest.skip('disabled')

    def test_doNotNeedToBeSigned(self):
        self.checkDoesNotNeedToBeSigned(
            # nobots|unsigned template for section after empty line
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:PM3&diff=prev&oldid=191418336&diffmode=source'
        )

        self.checkDoesNotNeedToBeSigned(
            # User adds nobots template in sleep period
            'https://de.wikipedia.org/w/index.php?title=Diskussion:Mordfall_Walter_L%C3%BCbcke&diff=prev&oldid=190730837'
        )
        self.checkDoesNotNeedToBeSigned(
            # User adds archive link at the top of talk page
            'https://de.wikipedia.org/w/index.php?title=Diskussion:Bengaluru&diff=prev&oldid=190437325&diffmode=source'
        )
        self.checkDoesNotNeedToBeSigned(
            # User adds text on own talk page at top
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:Matthias_v.d._Elbe&diff=prev&oldid=190432992&diffmode=source'
        )
        self.checkDoesNotNeedToBeSigned(
            # {{nobots|unsigned}} global
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:Count_Count/Sandbox&diff=prev&oldid=190431234&diffmode=source'
        )
        self.checkDoesNotNeedToBeSigned(
            # {{nobots|unsigned}} section
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:Count_Count/Sandbox&diff=prev&oldid=190427538&diffmode=source'
        )
        self.checkDoesNotNeedToBeSigned(
            # signed by other user within delay
            'https://de.wikipedia.org/w/index.php?title=Diskussion:Costa_Cordalis&diff=prev&oldid=190102321&diffmode=source'
        )
        self.checkDoesNotNeedToBeSigned(
            # insertion of welcome box withouth proper signature but excluded per regex
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:Kastriota&oldid=190247918')
        self.checkDoesNotNeedToBeSigned(
            # Portal discussion page abused as archive
            'https://de.wikipedia.org/w/index.php?title=Portal_Diskussion:Hannover/Artikel_des_Monats&diff=prev&oldid=190023146&diffmode=source')
        self.checkDoesNotNeedToBeSigned(
            # Portal discussion page abused as archive (II)
            'https://de.wikipedia.org/w/index.php?title=Portal_Diskussion:Rheinhessen/Neue_Artikel&diff=prev&oldid=187852104&diffmode=source')
        self.checkDoesNotNeedToBeSigned(
            # Inserted comment (reorganized) with same timestamp
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:Sperrpr%C3%BCfung&diff=prev&oldid=189833590&diffmode=source')
        self.checkDoesNotNeedToBeSigned(
            # subst:OTRS
            'https://de.wikipedia.org/w/index.php?title=Diskussion:Centrum_f%C3%BCr_Asienwissenschaften_und_Transkulturelle_Studien&oldid=189740023')
        self.checkDoesNotNeedToBeSigned(
            # template at the beginning
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion:146.185.69.133&diff=prev&oldid=189565765&diffmode=source')
        self.checkDoesNotNeedToBeSigned(
            # _ in special directive
            'https://de.wikipedia.org/w/index.php?title=Diskussion%3APostgender&diff=prev&oldid=189397879')
        self.checkDoesNotNeedToBeSigned(
            # moved text
            'https://de.wikipedia.org/w/index.php?title=Wikipedia%3AVandalismusmeldung&diff=prev&oldid=189343072')
        self.checkDoesNotNeedToBeSigned(
            # Postscriptum
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:L%C3%B6schkandidaten/11._Juni_2019&diff=prev&oldid=189460775&diffmode=source')
        self.checkDoesNotNeedToBeSigned(
            # Postscriptum
            'https://de.wikipedia.org/w/index.php?title=Wikipedia_Diskussion:Wiki_Loves_Earth_2019/Deutschland/Organisation&diff=prev&oldid=189464146&diffmode=source')
        self.checkDoesNotNeedToBeSigned(
            # line inserted in own section
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:Caf%C3%A9&diff=prev&oldid=189588024&diffmode=source')

#    @unittest.skip('disabled')
    def test_needsUserOnlySigning(self):
        self.checkNeedsUserOnlySigning(
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:Bots/Antr%C3%A4ge_auf_Botflag&diff=prev&oldid=189592572&diffmode=source')  # on opt-in page
        self.checkNeedsUserOnlySigning(
            'https://de.wikipedia.org/w/index.php?title=Wikipedia:L%C3%B6schkandidaten/5._Juni_2019&diff=prev&oldid=189333235&diffmode=source')

#    @unittest.skip('disabled')
    def test_needsTimestampOnlySigning(self):
        self.checkNeedsTimestampOnlySigning(
            'https://de.wikipedia.org/w/index.php?title=Portal_Diskussion:Fu%C3%9Fball&diff=prev&oldid=190210122&diffmode=source')

#    @unittest.skip('disabled')
    def test_allNeedToBeFullySigned(self):
        text = pywikibot.Page(
            self.controller.site,
            'Benutzer:CountCountBot/Testcases/Beiträge die komplett nachsigniert werden dürfen'
        ).get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+',
            re.I).findall(text)
        for match in matches:
            self.checkNeedsToBeFullySigned(match)

#    @unittest.skip('disabled')
    def test_allDoNotNeedToBeSigned(self):
        text = pywikibot.Page(
            self.controller.site,
            'Benutzer:CountCountBot/Testcases/Beiträge die nicht nachsigniert werden dürfen'
        ).get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+',
            re.I).findall(text)
        for match in matches:
            self.checkDoesNotNeedToBeSigned(match)

#    @unittest.skip('disabled')
    def test_allNeedUserOnlySigning(self):
        text = pywikibot.Page(
            self.controller.site,
            'Benutzer:CountCountBot/Testcases/Beiträge die als ohne Benutzerinformation nachsigniert werden dürfen'
        ).get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+',
            re.I).findall(text)
        for match in matches:
            self.checkNeedsUserOnlySigning(match)

#    @unittest.skip('disabled')
    def test_allNeedTimestampOnlySigning(self):
        text = pywikibot.Page(
            self.controller.site,
            'Benutzer:CountCountBot/Testcases/Beiträge die als ohne Zeitstempel nachsigniert werden dürfen'
        ).get(force=True)
        matches = re.compile(
            r'https://de.wikipedia.org/w/index\.php\?title=[^] \n]+',
            re.I).findall(text)
        for match in matches:
            self.checkNeedsTimestampOnlySigning(match)

#    @unittest.skip('disabled')
    def test_timestampMatching(self):
        date = datetime.datetime.now()
        d = datetime.timedelta(days=1)
        for i in range(1, 365):
            date += d
            with self.subTest(date=date):
                s = BotThread.getSignatureTimestampString(date.timestamp())
                self.assertTrue(BotThread.hasAnySignatureTimestamp(s),
                                '\nTimestamp does not match regex: {}'
                                .format(s))


if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        pywikibot.stopme()
