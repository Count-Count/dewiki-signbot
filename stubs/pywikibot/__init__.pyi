from typing import Optional, Pattern
import datetime
from pywikibot.logging import output, error, exception, log, warning
from pywikibot.exceptions import Error, EditConflict, NoPage
from pywikibot.page import Page, User, Link
from pywikibot.mypy import RecentChangesInfo
from pywikibot.site import BaseSite
from pywikibot.bot import handle_args
from pywikibot.data.api import APIError
from pywikibot.comms.eventstreams import site_rc_listener
import pywikibot.textlib as textlib

def Site(
    code: Optional[str] = None,
    fam: Optional[str] = None,
    user: Optional[str] = None,
    sysop: Optional[str] = None,
    interface: Optional[str] = None,
    url: Optional[str] = None,
) -> BaseSite: ...

__all__ = (
    "BadTitle",
    "Bot",
    "calledModuleName",
    "CaptchaError",
    "CascadeLockedPage",
    "Category",
    "CircularRedirect",
    "Claim",
    "config",
    "CoordinateGlobeUnknownException",
    "critical",
    "CurrentPageBot",
    "debug",
    "EditConflict",
    "error",
    "Error",
    "exception",
    "FatalServerError",
    "FilePage",
    "handle_args",
    "handleArgs",
    "html2unicode",
    "input",
    "input_choice",
    "input_yn",
    "inputChoice",
    "InterwikiRedirectPage",
    "InvalidTitle",
    "IsNotRedirectPage",
    "IsRedirectPage",
    "ItemPage",
    "Link",
    "LockedNoPage",
    "LockedPage",
    "log",
    "NoCreateError",
    "NoMoveTarget",
    "NoPage",
    "NoSuchSite",
    "NoUsername",
    "OtherPageSaveError",
    "output",
    "Page",
    "PageCreatedConflict",
    "PageDeletedConflict",
    "PageNotSaved",
    "PageRelatedError",
    "PageSaveRelatedError",
    "PropertyPage",
    "QuitKeyboardInterrupt",
    "SectionError",
    "Server504Error",
    "ServerError",
    "showHelp",
    "Site",
    "SiteDefinitionError",
    "SiteLink",
    "SpamfilterError",
    "stdout",
    "TitleblacklistError",
    "translate",
    "ui",
    "unicode2html",
    "UnicodeMixin",
    "UnknownExtension",
    "UnknownFamily",
    "UnknownSite",
    "UnsupportedPage",
    "UploadWarning",
    "url2unicode",
    "User",
    "UserActionRefuse",
    "UserBlocked",
    "warning",
    "WikiBaseError",
    "WikidataBot",
)

def stopme() -> None: ...
def showDiff(oldtext: str, newtext: str, context: int = 0) -> None: ...

link_regex: Pattern[str]

class Timestamp(datetime.datetime): ...
