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
import re
import unittest
from urllib.parse import parse_qs, urlparse

import pywikibot

from signbot import BotThread, Controller, RevisionInfo


class TestSigning(unittest.TestCase):

    def setUp(self):
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
        self.controller.site.loadrevisions(page, startid=revId, total=1)
        newRevision = page._revisions[revId]
        epoch = datetime.datetime.utcfromtimestamp(0)
        oldRevId = newRevision.parent_id
        return RevisionInfo(
            page.namespace(), page.title(), 'new' if oldRevId == 0 else 'edit',
            False, newRevision.comment, newRevision.user, oldRevId, revId,
            (newRevision.timestamp - epoch).total_seconds())

    def checkNeedsToBeFullySigned(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        self.assertTrue(
            res,
            'Should need full signing but not recognized as unsigned: {}'
            .format(pageUrl))
        self.assertFalse(shouldBeHandledResult.isAlreadyTimeSigned,
                         "Should not be timestamp signed but is: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyUserSigned,
                         "Should not be user signed but is: %s" % pageUrl)

    def checkNeedsUserOnlySigning(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        self.assertTrue(
            res,
            'Should need user signing but not recognized as unsigned: {}'
            .format(pageUrl))
        self.assertTrue(shouldBeHandledResult.isAlreadyTimeSigned,
                        "Should be timestamp signed but is not: %s" % pageUrl)
        self.assertFalse(shouldBeHandledResult.isAlreadyUserSigned,
                         "Should not be user signed but is: %s" % pageUrl)

    def checkNeedsTimestampOnlySigning(self, pageUrl):
        rev = self.getRevisionInfo(pageUrl)
        bt = BotThread(self.controller.site, rev, self.controller)
        (res, shouldBeHandledResult) = bt.changeShouldBeHandled()
        self.assertTrue(
            res,
            'Should need timestamp signing but not recognized as unsigned: {}'
            .format(pageUrl))
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
            # _ in special directive
            'https://de.wikipedia.org/w/index.php?title=Benutzer_Diskussion%3AAgathenon&diff=prev&oldid=189352195')

#    @unittest.skip('disabled')
    def test_doNotNeedToBeSigned(self):
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
        for i in range(1, 250):
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
