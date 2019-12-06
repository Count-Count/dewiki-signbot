#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) Count Count, 2019
#
# Original code by zhuyifei1999
# (https://wikitech.wikimedia.org/wiki/User:Zhuyifei1999)
# Heavily modified by Count Count
# (https://de.wikipedia.org/wiki/Benutzer:Count_Count)
#
# DUAL LICENSED: You are free to choose either or both of below licenses:
#
# 1.
#
# Distributed under the terms of
# Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# https://creativecommons.org/licenses/by-sa/3.0/
#
# 2.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General License for more details.
#
# You should have received a copy of the GNU General License
# along with self program.  If not, see <http://www.gnu.org/licenses/>
#

from dataclasses import dataclass
from typing import Any, Tuple, List, Optional, cast, Iterator, Callable, Pattern
from datetime import datetime
from datetime import timedelta
import os
import re
import time
import signal
import threading
import hashlib
import base64
import locale
import traceback
import sched
import pytz
from redis import Redis
import pywikibot
from pywikibot.bot import SingleSiteBot
from pywikibot.diff import PatchManager
from pywikibot.comms.eventstreams import site_rc_listener


TIMEOUT = 600  # We expect at least one rc entry every 10 minutes


class ReadingRecentChangesTimeoutError(Exception):
    pass


def on_timeout(signum: Any, frame: Any) -> None:
    raise ReadingRecentChangesTimeoutError


@dataclass
class RevisionInfo:
    namespace: int
    title: str
    type: str
    bot: bool
    comment: str
    user: str
    oldRevision: Optional[int]
    newRevision: int
    timestamp: int

    @staticmethod
    def fromRecentChange(change: "pywikibot.mypy.RecentChangesInfo") -> "RevisionInfo":
        return RevisionInfo(
            change["namespace"],
            change["title"],
            change["type"],
            change["bot"],
            change["comment"],
            change["user"],
            change["revision"]["old"] if change["type"] == "edit" else None,
            change["revision"]["new"],
            change["timestamp"],
        )


class Controller(SingleSiteBot):
    """The Signbot class."""

    doEdits = True
    doNotify = os.name != "nt"

    def __init__(self) -> None:
        site = pywikibot.Site(user="SignaturBot")
        super(Controller, self).__init__(site=site)
        self.reloadRegex()
        self.reloadOptOut()
        self.reloadOptIn()
        self.botkey = os.environ.get("REDIS_KEY")
        if not self.botkey:
            raise Exception("REDIS_KEY environment variable not set")
        self.redis = Redis(host="tools-redis" if os.name != "nt" else "localhost")
        self.generator = FaultTolerantLiveRCPageGenerator(self.site)
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.stopped = False
        self.lastQueueIdleTime: datetime
        self.excluderegex: List[Pattern[str]]

    def processQueue(self) -> None:
        while not self.stopped:
            try:
                self.lastQueueIdleTime = datetime.now()
                self.scheduler.run(blocking=False)
                time.sleep(1)
            except Exception:
                pywikibot.error("Error during processing queue: %s " % traceback.format_exc())
                time.sleep(10)

    def setup(self) -> None:
        """Setup the bot."""
        if os.name != "nt":
            signal.signal(signal.SIGALRM, on_timeout)  # pylint: disable=E1101
            signal.alarm(TIMEOUT)  # pylint: disable=E1101

    def skip_page(self, page: pywikibot.Page) -> bool:
        """Skip special/media pages"""
        if page.namespace() < 0:
            return True
        elif not page.exists():
            return True
        elif page.isRedirectPage():
            return True
        return super().skip_page(page)

    def run(self) -> None:
        self.lastQueueIdleTime = datetime.now()
        threading.Thread(target=self.processQueue).start()
        super().run()

    def exit(self) -> None:
        self.stopped = True
        super().exit()

    def treat(self, page: pywikibot.Page) -> None:
        """Process a single Page object from stream."""
        change = page._rcinfo

        if os.name != "nt":
            signal.alarm(TIMEOUT)  # pylint: disable=E1101

        if change["namespace"] == 2 and change["title"] == ("Benutzer:SignaturBot/exclude regex"):
            pywikibot.output("exclude regex page changed")
            self.scheduler.enter(10, 1, self.reloadRegex)

        elif change["namespace"] == 2 and change["title"] == ("Benutzer:SignaturBot/Opt-Out"):
            pywikibot.output("opt-out page changed")
            self.scheduler.enter(10, 1, self.reloadOptOut)

        elif change["namespace"] == 2 and change["title"] == ("Benutzer:SignaturBot/Opt-In"):
            pywikibot.output("opt-in page changed")
            self.scheduler.enter(10, 1, self.reloadOptIn)

        # Talk page or project page, bot edits excluded
        elif (
            (not change["bot"])
            and (change["namespace"] == 4 or change["namespace"] % 2 == 1 or change["title"] in self.pageoptin)
            and (change["type"] in ["edit", "new"])
            and ("nosig!" not in change["comment"])
            and (not change["comment"].startswith("Bot: "))
        ):
            t = EditItem(self.site, RevisionInfo.fromRecentChange(change), self)
            self.scheduler.enter(10, 1, t.checkEdit)
            if datetime.now() - self.lastQueueIdleTime > timedelta(minutes=1):
                pywikibot.warning(
                    "Queue idle longer than one minute ago: %s, queue depth: %d"
                    % (str(datetime.now() - self.lastQueueIdleTime), len(self.scheduler.queue))
                )

    def teardown(self) -> None:
        """Bot has finished due to unknown reason."""
        if self._generator_completed:
            pywikibot.log("Main thread exit - THIS SHOULD NOT HAPPEN")
            time.sleep(10)

    def reloadRegex(self) -> None:
        pywikibot.output("Reloading exclude regex")
        # We do not directly assign to self.controller.excluderegex right
        # now to avoid issues with multi-threading
        lst = []
        repage = pywikibot.Page(self.site, "User:SignaturBot/exclude_regex")
        for line in repage.get(force=True).split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                lst.append(re.compile(line, re.I))
        lst.append(re.compile(r"{{(?:Vorlage:)?nobots\|unsigned}}", re.I))
        self.excluderegex = lst

    def reloadOptOut(self) -> None:
        pywikibot.output("Reloading optout list")
        optoutPage = pywikibot.Page(self.site, "User:SignaturBot/Opt-Out")
        newuseroptout = set()
        newpageoptout = set()
        for wikilink in pywikibot.link_regex.finditer(
            pywikibot.textlib.removeDisabledParts(optoutPage.get(force=True))
        ):
            if not wikilink.group("title").strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group("title"), source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            if link.namespace == 2:
                newuseroptout.add(link.title.strip())
            else:
                newpageoptout.add(link.ns_title(onsite=self.site).strip())
        self.useroptout = newuseroptout
        self.pageoptout = newpageoptout

    def reloadOptIn(self) -> None:
        pywikibot.output("Reloading optin list")
        optinPage = pywikibot.Page(self.site, "User:SignaturBot/Opt-In")
        newpageoptin = set()
        for wikilink in pywikibot.link_regex.finditer(pywikibot.textlib.removeDisabledParts(optinPage.get(force=True))):
            if not wikilink.group("title").strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group("title"), source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            if link.namespace != 0:
                newpageoptin.add(link.ns_title(onsite=self.site).strip())
        self.pageoptin = newpageoptin

    def hash(self, s: str) -> str:
        return base64.b64encode(hashlib.sha224(s.encode("utf-8")).digest()).decode("ascii")

    def getKey(self, user: pywikibot.User) -> str:
        assert self.botkey is not None
        return self.hash(self.botkey) + ":" + self.hash(self.botkey + ":" + user.username)

    def isExperiencedUser(self, user: pywikibot.User) -> bool:
        return not user.isAnonymous() and user.editCount() > 500

    def checknotify(self, user: pywikibot.User) -> bool:
        if not Controller.doNotify:
            return False
        if user.isAnonymous():
            return False
        if self.isExperiencedUser(user):
            return False
        reset = int(time.time()) + 60 * 60 * 24 * 30
        key = self.getKey(user)
        p = self.redis.pipeline()  # type: ignore
        p.incr(key)
        p.expireat(key, reset + 10)
        limitReached = p.execute()[0] >= 3
        if limitReached:
            p.delete(key)
            p.execute()
            return True
        else:
            return False

    def clearnotify(self, user: pywikibot.User) -> None:
        if not Controller.doNotify:
            return
        if user.isAnonymous():
            return
        key = self.getKey(user)
        p = self.redis.pipeline()  # type: ignore
        p.delete(key)
        p.execute()


class ShouldBeHandledResult:
    def __init__(self, tosignnum: int, tosignstr: str, isAlreadyTimeSigned: bool, isAlreadyUserSigned: bool) -> None:
        self.tosignnum = tosignnum
        self.tosignstr = tosignstr
        self.isAlreadyTimeSigned = isAlreadyTimeSigned
        self.isAlreadyUserSigned = isAlreadyUserSigned


class EditItem:
    timezone = pytz.timezone("Europe/Berlin")

    def __init__(self, site: pywikibot.site.BaseSite, revInfo: RevisionInfo, controller: Controller):
        self.site = site
        self.revInfo = revInfo
        self.controller = controller
        self.page: pywikibot.Page
        self.shouldBeHandledResult: Optional[ShouldBeHandledResult]

    def changeShouldBeHandled(self) -> Tuple[bool, Optional[ShouldBeHandledResult]]:
        self.page = pywikibot.Page(self.site, self.revInfo.title, ns=self.revInfo.namespace)
        self.output("Handling")

        if self.isPageOptOut():
            self.output("Page %s on opt-out list" % self.page.title())
            return False, None

        if (
            self.page.title().find("/Archiv/") > 0
            or self.page.title().find("/Archiv ") > 0
            or self.page.title().endswith("/Archiv")
        ):
            self.output("Suspected archive page")
            return False, None

        if self.page.title().startswith("Portal Diskussion:") and (
            self.page.title().endswith("/Artikel des Monats") or self.page.title().endswith("/Neue Artikel")
        ):
            return False, None

        if self.page.isRedirectPage():
            self.output("Redirect")
            return False, None
        if self.page.namespace() == 4:
            # Project pages needs attention (__NEWSECTIONLINK__)
            if not self.isDiscussion():
                self.output("Not a discussion")
                return False, None

        if {"mw-undo", "mw-rollback"}.intersection(self.getTags()):
            self.output("undo / rollback")
            return False, None

        user = pywikibot.User(self.site, self.revInfo.user)
        if self.isUserOptOut(user.username):
            self.output("%s opted-out" % user.username)
            return False, None

        if (
            self.page.namespace() == pywikibot.site.Namespace.USER_TALK
            and self.page.title(with_ns=False) == user.username
            and self.controller.isExperiencedUser(user)
        ):
            self.output("Experienced user %s edited own talk page" % user.username)
            return False, None

        # diff-reading.
        if self.revInfo.type == "new":
            old_text = ""
        else:
            assert self.revInfo.oldRevision is not None
            try:
                old_text = self.page.getOldVersion(self.revInfo.oldRevision)
            except KeyError:
                self.warning("Old revision %d not found, retrying..." % self.revInfo.oldRevision)
                time.sleep(10)
                old_text = self.page.getOldVersion(self.revInfo.oldRevision)

        try:
            new_text = self.page.getOldVersion(self.revInfo.newRevision)
        except KeyError:
            self.warning("New revision %d not found, retrying..." % self.revInfo.newRevision)
            time.sleep(10)
            new_text = self.page.getOldVersion(self.revInfo.newRevision)

        new_lines = new_text.split("\n")
        diff = PatchManager(old_text.split("\n") if old_text else [], new_lines, by_letter=True)
        #        diff.print_hunks()

        tosignstr = ""
        tosignnum = -1

        if len(diff.hunks) > 1:
            self.output("Multiple diff hunks %d" % len(diff.blocks))
            return False, None

        hunk = diff.hunks[0]
        group = hunk.group

        timestamp1 = self.getSignatureTimestampString(self.revInfo.timestamp)
        timestamp2 = self.getSignatureTimestampString(self.revInfo.timestamp - 60)

        exactTimeSigned = False
        timeSigned = False
        userSigned = False

        signatureTimestampCount = 0

        for tag, _, _, j1, j2 in group:
            if tag == "insert":
                insertStartLine = j1
                for j in range(j1, j2):
                    line = hunk.b[j]
                    if self.page == user.getUserTalkPage() or self.page.title().startswith(
                        user.getUserTalkPage().title() + "/"
                    ):
                        if "{{" in line.lower():
                            self.output("User adding templates to their " "own talk page -- ignored")
                            return False, None

                    excluderegextest = self.matchExcludeRegex(line)
                    if excluderegextest is not None:
                        self.output("Matches %s -- ignored" % excluderegextest)
                        return False, None

                    if self.isNotExcludedLine(line):
                        tosignnum = j
                        tosignstr = line

                        exactTimeSigned = tosignstr.find(timestamp1) >= 0 or tosignstr.find(timestamp2) >= 0

                        lineTimeSigned = self.hasAnySignatureTimestamp(line)
                        if lineTimeSigned:
                            signatureTimestampCount += 1
                        timeSigned = timeSigned or lineTimeSigned

                        userSigned = userSigned or self.isUserSigned(user, tosignstr)
                        if timeSigned and userSigned:
                            self.controller.clearnotify(user)
                            self.output("Already signed")
                            return False, None

            if tag == "delete":
                self.output("Line deletion found")
                return False, None
            if tag == "replace":
                self.output("Line replacement found")
                return False, None

        if not tosignstr:
            self.output("No inserts")
            return False, None

        if signatureTimestampCount > 1:
            self.output("Multiple timestamps found")
            return False, None

        if self.hasAnySignatureAllowedUserLink(tosignstr) and timeSigned and self.controller.isExperiencedUser(user):
            self.output("Timestamp and other user link found - likely copied")
            return False, None

        if not timeSigned and not userSigned:
            if self.isAlreadySignedInFollowingLines(user, new_lines, tosignnum):
                return False, None

        if not timeSigned and not userSigned and self.isPostscriptum(tosignstr) and tosignnum > 1:
            checkLineNo = tosignnum - 1
            if not new_lines[checkLineNo].strip() and checkLineNo > 0:
                checkLineNo -= 1
            if self.isUserSigned(user, new_lines[checkLineNo]) and self.hasAnySignatureTimestamp(
                new_lines[checkLineNo]
            ):
                self.output("Postcriptum found")
                return False, None

        if not timeSigned:
            precedingSignatureOrSectionFound = False
            for i in range(0, insertStartLine):
                if new_lines[i].strip().startswith("=="):
                    precedingSignatureOrSectionFound = True
                    break
                if self.hasAnySignature(new_lines[i]):
                    precedingSignatureOrSectionFound = True
                    break
            followingSignatureOrSectionFound = False
            for i in range(tosignnum + 1, len(new_lines)):
                if new_lines[i].strip().startswith("=="):
                    followingSignatureOrSectionFound = True
                    break
                if self.hasAnySignature(new_lines[i]):
                    followingSignatureOrSectionFound = True
                    break
            if not precedingSignatureOrSectionFound:
                if (
                    new_lines[insertStartLine].strip().startswith("{{") or tosignstr.strip().startswith("{{")
                ) and tosignstr.strip().endswith("}}"):
                    self.output("Insertion of template at beginning of page")
                    return False, None
                if followingSignatureOrSectionFound and self.controller.isExperiencedUser(user):
                    self.output(
                        "Insertion by experienced user at the beginning of talk page before any sections or signatures"
                    )
                    return False, None

        if self.hasApplicableNobotsTemplate(new_lines, insertStartLine):
            return False, None

        # if not user-signed don't consider
        if not userSigned and timeSigned and not exactTimeSigned:
            timeSigned = False

        # all checks passed
        return True, ShouldBeHandledResult(tosignnum, tosignstr, timeSigned, userSigned)

    def hasApplicableNobotsTemplate(self, new_lines: List[str], insertStartLine: int) -> bool:
        for line in new_lines:
            if re.search(r"{{(?:Vorlage:)?nobots\|unsigned}}", line, re.I):
                self.output("Global {{nobots|unsigned}} found")
                return True
            elif line.startswith("="):
                break

        secIndex = 1000
        if insertStartLine > 1:
            for i in range(insertStartLine - 2, -1, -1):
                line = new_lines[i].strip()
                match = re.match(r"^(=+).*[^=](=+)$", line)
                if match and len(match.group(1)) == len(match.group(2)) and len(match.group(1)) < secIndex:
                    # skip empty lines
                    checkLineForBotsDirectiveIndex = i + 1
                    while checkLineForBotsDirectiveIndex < insertStartLine - 1:
                        if new_lines[checkLineForBotsDirectiveIndex].strip():
                            break
                        checkLineForBotsDirectiveIndex += 1
                    lineAfterSectionStart = new_lines[checkLineForBotsDirectiveIndex].strip()
                    if re.search(r"{{(?:Vorlage:)?nobots\|unsigned}}", lineAfterSectionStart, re.I):
                        self.output("{{nobots|unsigned}} found for section %s" % line)
                        return True
                    secIndex = len(match.group(1))
        return False

    def isAlreadySignedInFollowingLines(self, user: pywikibot.User, new_lines: List[str], tosignnum: int) -> bool:
        for lineNo in range(tosignnum + 1, len(new_lines)):
            line = new_lines[lineNo].strip()
            if self.isUserSigned(user, line) and self.hasAnySignatureTimestamp(line):
                self.output("Found user's signature in lines after edit")
                return True
            elif self.hasUnsignedTemplateForUser(user, line):
                self.output("Found signed template for user in lines after edit")
                return True
            elif line.startswith("="):
                # new section found
                return False
            elif self.hasAnySignatureTimestamp(line):
                # other signature found
                return False
        return False

    def continueSigningGetLineIndex(
        self,
        user: pywikibot.User,
        shouldBeHandledResult: ShouldBeHandledResult,
        currenttext: List[str],
        latestRevisionId: int,
    ) -> int:
        if latestRevisionId != self.revInfo.newRevision:
            # check edits which have occurred since unsigned edit for revert
            revs = self.getRevisions(latestRevisionId, self.revInfo.newRevision)
            for rev in revs:
                if (
                    rev["revid"] != self.revInfo.newRevision
                    and ("mw-rollback" in rev["tags"] or "mw-undo" in rev["tags"])
                    and self.isUserSigned(user, rev["comment"])
                ):
                    return -1
        if (
            shouldBeHandledResult.tosignnum < len(currenttext)
            and currenttext[shouldBeHandledResult.tosignnum] == shouldBeHandledResult.tosignstr
        ):
            tosignindex = shouldBeHandledResult.tosignnum
        elif currenttext.count(shouldBeHandledResult.tosignstr) == 1:
            # line not at same position but just one line with same text found,
            # assuming that it is the line to be signed
            tosignindex = currenttext.index(shouldBeHandledResult.tosignstr)
        else:
            self.output("Line no longer found, probably signed")
            return -1
        if self.isAlreadySignedInFollowingLines(user, currenttext, tosignindex):
            return -1
        if self.hasApplicableNobotsTemplate(currenttext, tosignindex):
            return -1
        return tosignindex

    def runWrapped(self, func: Callable[[], None]) -> None:
        try:
            startTime = datetime.now()
            func()
            if datetime.now() - startTime > timedelta(seconds=60):
                self.warning("Execution elapsed %s" % (str(datetime.now() - startTime)))
        except Exception:
            self.error(traceback.format_exc())

    def checkEdit(self) -> None:
        self.runWrapped(self.checkEdit0)

    def checkEdit0(self) -> None:
        res, self.shouldBeHandledResult = self.changeShouldBeHandled()
        if not res:
            return

        self.output("Waiting")
        if Controller.doEdits:
            self.controller.scheduler.enter(5 * 60, 1, self.continueAferDelay)

    def continueAferDelay(self) -> None:
        self.runWrapped(self.continueAferDelay0)

    def continueAferDelay0(self) -> None:
        self.output("Woke up")
        assert self.shouldBeHandledResult is not None
        while True:
            try:
                user = pywikibot.User(self.site, self.revInfo.user)
                currenttext = self.page.get(force=True).split("\n")
                tosignindex = self.continueSigningGetLineIndex(
                    user, self.shouldBeHandledResult, currenttext, self.page.latest_revision_id
                )
                if tosignindex < 0:
                    return
                currenttext[tosignindex] += self.getSignature(
                    self.shouldBeHandledResult.tosignstr,
                    user,
                    self.shouldBeHandledResult.isAlreadyTimeSigned,
                    self.shouldBeHandledResult.isAlreadyUserSigned,
                )

                self.output("Signing")

                originalSummary = ': "%s"' % self.revInfo.comment if len(self.revInfo.comment.strip()) > 0 else ""

                summary = "Bot: Signaturnachtrag für Beitrag von %s%s" % (self.userlink(user), originalSummary)

                #                if self.page.title().startswith('Benutzer Diskussion:Count Count/'):
                if Controller.doEdits:
                    self.userPut(self.page, self.page.get(), "\n".join(currenttext), summary=summary, botflag=False)
                break
            except pywikibot.EditConflict:
                self.output("Edit conflict - retrying...")
                continue
            except pywikibot.NoPage:
                self.output("Page ceased to exist.")
                return

        notify = self.controller.checknotify(user)
        if notify:
            self.output("Notifying %s" % user)
            talk = user.getUserTalkPage()
            if talk.isRedirectPage():
                talk = talk.getRedirectTarget()
            try:
                talktext = talk.get(force=True, get_redirect=True) + "\n\n"
            except pywikibot.NoPage:
                talktext = ""

            talktext += "{{subst:Unterschreiben}}"
            #            if self.page.title().startswith('Benutzer Diskussion:SignaturBot/'):
            if Controller.doEdits:
                self.userPut(
                    talk,
                    talk.text,
                    talktext,
                    summary="Bot: Hinweis zum [[Hilfe:Signatur|Unterschreiben von Diskussionbeiträgen]] ergänzt",
                    minor=False,
                    botflag=False,
                )

    def isPostscriptum(self, line: str) -> bool:
        return (
            re.match(r"^(:+\s*)?(PS|P\. ?S\.|Nachtrag|Postscriptum|Notabene|NB|N\. ?B\.):?\s*\S", line, re.I)
            is not None
        )

    def output(self, info: str) -> None:
        pywikibot.output("%s: %s" % (self.page, info))

    def error(self, info: str) -> None:
        pywikibot.error("%s: %s" % (self.page, info))

    def warning(self, info: str) -> None:
        pywikibot.warning("%s: %s" % (self.page, info))

    def getRevisions(self, rvstartid: int, rvendid: int):
        req = self.site._simple_request(
            action="query",
            prop="revisions",
            titles=self.page,
            rvprop="ids|timestamp|flags|comment|user|tags|flagged",
            rvstartid=rvstartid,
            rvendid=rvendid,
            rvlimit=1,
        )
        res = req.submit()
        pages = res["query"]["pages"]
        revisions = pages[list(pages.keys())[0]]["revisions"]
        return revisions

    def getTags(self) -> List[str]:
        try:
            try:
                r = self.getRevisions(self.revInfo.newRevision, self.revInfo.newRevision)
            except pywikibot.data.api.APIError as e:
                if e.code == "badid_rvstartid":
                    self.output("getTags() rvstartid not found. Retrying... ")
                    time.sleep(10)
                    r = self.getRevisions(self.revInfo.newRevision, self.revInfo.newRevision)
                else:
                    raise
        except Exception as e:
            pywikibot.exception(e)
            return []
        else:
            try:
                return cast(List[str], r[0]["tags"])
            except KeyError:
                return []

    def getSignature(
        self, tosignstr: str, user: pywikibot.User, isAlreadyTimeSigned: bool, isAlreadyUserSigned: bool
    ) -> str:
        p = ""
        if tosignstr[-1] != " ":
            p = " "
        timestamp = self.getSignatureTimestampString(self.revInfo.timestamp)
        if isAlreadyTimeSigned:
            altText = "|ALT=unvollständig"
            timeInfo = ""
        elif isAlreadyUserSigned:
            altText = "|ALT=ohne (gültigen) Zeitstempel"
            timeInfo = "|" + timestamp
        else:
            altText = ""
            timeInfo = "|" + timestamp

        return p + "{{unsigniert|%s%s%s}}" % (user.username, timeInfo, altText)

    @staticmethod
    def getSignatureTimestampString(timestamp: int) -> str:
        localizedTime = pytz.utc.localize(pywikibot.Timestamp.utcfromtimestamp(timestamp)).astimezone(EditItem.timezone)
        abbrevDot = "" if localizedTime.month == 5 else "."  # no abbrev dot for Mai
        if os.name == "nt":
            return (
                localizedTime.strftime("%H:%M, ")
                + localizedTime.strftime("%e").replace(" ", "")
                + localizedTime.strftime(". %b" + abbrevDot + " %Y (%Z)")
            ).replace("Mrz", "Mär")
        else:
            return localizedTime.strftime("%H:%M, %-d. %b" + abbrevDot + " %Y (%Z)")

    def userlink(self, user: pywikibot.User) -> str:
        if user.isAnonymous():
            return "[[Special:Contributions/%s|%s]]" % (user.username, user.username)
        else:
            return "[[User:%s|%s]]" % (user.username, user.username)

    def isUserSigned(self, user: pywikibot.User, tosignstr: str) -> bool:
        for wikilink in pywikibot.link_regex.finditer(pywikibot.textlib.removeDisabledParts(tosignstr)):
            if not wikilink.group("title").strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group("title"), source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            #            if link.site != self.site: continue
            if user.isAnonymous():
                if link.namespace != -1:
                    continue
                if link.title != "Beiträge/" + user.username:
                    continue
            else:
                if link.namespace == -1 and link.title == "Beiträge/" + user.username:
                    return True
                if link.namespace not in [2, 3]:
                    continue
                if link.title != user.username:
                    continue
            return True

        return False

    def hasAnySignature(self, text: str) -> bool:
        return self.hasAnySignatureAllowedUserLink(text) and self.hasAnySignatureTimestamp(text)

    def hasAnySignatureAllowedUserLink(self, text: str) -> bool:
        for wikilink in pywikibot.link_regex.finditer(text):
            if not wikilink.group("title").strip():
                continue
            try:
                link = pywikibot.Link(wikilink.group("title"), source=self.site)
                link.parse()
            except pywikibot.Error:
                continue
            # Certain Bot signatures lead to subpages sometimes
            if link.namespace in [2, 3] and link.title.find("/") == -1:
                return True
            if link.namespace == -1 and link.title.startswith("Beiträge/"):
                return True
        return False

    @staticmethod
    def hasAnySignatureTimestamp(line: str) -> bool:
        return (
            re.search(
                r"[0-9]{2}:[0-9]{2}, [123]?[0-9]\. (?:Jan\.|Feb\.|Mär\.|Apr\.|Mai|Jun\.|Jul\.|Aug\.|Sep\.|Okt\.|Nov\.|Dez\.) 2[0-9]{3} \((CES?T|MES?Z)\)",
                line,
            )
            is not None
        )

    @staticmethod
    def hasUnsignedTemplateForUser(user: pywikibot.User, line: str) -> bool:
        match = re.search(r"{{(?:Vorlage:)?(?:unsigniert|unsigned)\|([^|}]+)", line)
        if match:
            if user.isAnonymous():
                return match.group(1).strip().lower() == user.username.lower()
            else:
                return match.group(1).strip() == user.username
        return False

    def isNotExcludedLine(self, line: str) -> bool:
        # remove non-functional parts and categories
        tempstr = re.sub(r"\[\[[Kk]ategorie:[^\]]+\]\]", "", pywikibot.textlib.removeDisabledParts(line)).strip()
        tempstr = re.sub(r"<br\s*/>", "", tempstr)
        tempstr = re.sub(r"\[\[(Datei|File):([^\]\[]|(\[\[[^\]]+\]\]))+\]\]", "", tempstr, 0, re.I)
        # not empty
        if not tempstr:
            return False
        # not heading
        if tempstr.startswith("=") and tempstr.endswith("="):
            return False
        # not table/template
        if tempstr.startswith("!") or tempstr.startswith("|") or tempstr.startswith("{|") or tempstr.endswith("|"):
            return False
        # not horizontal line
        if tempstr.startswith("----"):
            return False
        # not magic words
        if re.match(r"^__[A-ZÄÖÜ_]+__$", tempstr):
            return False

        return True

    def isUserOptOut(self, user: str) -> bool:
        return user in self.controller.useroptout

    def isPageOptOut(self) -> bool:
        return self.page.title() in self.controller.pageoptout

    def isDiscussion(self) -> bool:
        # TODO: opt-in list

        # __NEWSECTIONLINK__ -> True
        if "newsectionlink" in self.page.properties():
            return True

        if self.page.title() in self.controller.pageoptin:
            return True

        if self.page.title().startswith("Wikipedia:Löschkandidaten/"):
            return True

        if self.page.title().startswith("Wikipedia:Qualitätssicherung/"):
            return True

        return False

    def matchExcludeRegex(self, line: str) -> Optional[str]:
        line = line.replace("_", " ")
        for regex in self.controller.excluderegex:
            reobj = regex.search(line)
            if reobj is not None:
                return reobj.group(0)
        return None

    def userPut(
        self,
        page: pywikibot.Page,
        oldtext: str,
        newtext: str,
        summary: Optional[str] = None,
        minor: bool = True,
        botflag: Optional[bool] = None,
    ) -> None:
        if oldtext == newtext:
            pywikibot.output("No changes were needed on %s" % page.title(as_link=True))
            return

        pywikibot.output("\n\n>>> \03{lightpurple}%s\03{default} <<<" % page.title(as_link=True))

        pywikibot.showDiff(oldtext, newtext)
        if summary:
            pywikibot.output("Summary: %s" % summary)

        page.text = newtext
        try:
            page.save(summary=summary, minor=minor, botflag=botflag)
        except pywikibot.EditConflict:
            raise
        except pywikibot.Error as e:
            pywikibot.output("Failed to save %s: %r: %s" % (page.title(as_link=True), e, e))


def FaultTolerantLiveRCPageGenerator(site: pywikibot.site.BaseSite) -> Iterator[pywikibot.Page]:
    for entry in site_rc_listener(site):
        # The title in a log entry may have been suppressed
        if "title" not in entry and entry["type"] == "log":
            continue
        try:
            page = pywikibot.Page(site, entry["title"], entry["namespace"])
        except Exception:
            pywikibot.warning("Exception instantiating page %s: %s" % (entry["title"], traceback.format_exc()))
            continue
        page._rcinfo = entry
        yield page


def main() -> None:
    locale.setlocale(locale.LC_ALL, "de_DE.utf8")
    pywikibot.handle_args()
    Controller().run()


if __name__ == "__main__":
    try:
        main()
    finally:
        pywikibot.stopme()
