from typing import Union, Optional, Literal, Any, Dict, TypedDict
from pywikibot.tools import ComparableMixin
import pywikibot

class Page:
    text: str
    _rcinfo: pywikibot.mypy.RecentChangesInfo
    _revisions: Dict[int, "Revision"]
    def __init__(
        self, source: Union[pywikibot.site.BaseSite, pywikibot.Page], title: str = "", ns: int = 0
    ) -> None: ...
    def exists(self) -> bool: ...
    def namespace(self) -> pywikibot.site.Namespace: ...
    def isRedirectPage(self) -> bool: ...
    def get(self, force: bool = False, get_redirect: bool = False, sysop: bool = False) -> str: ...
    def title(
        self,
        underscore: bool = False,
        with_ns: bool = True,
        with_section: bool = True,
        as_url: bool = False,
        as_link: bool = False,
        allow_interwiki: bool = True,
        force_interwiki: bool = False,
        textlink: bool = False,
        as_filename: bool = False,
        insite: Optional[pywikibot.site.BaseSite] = None,
        without_brackets: bool = False,
    ) -> str: ...
    def getRedirectTarget(self) -> "Page": ...
    def save(
        self,
        summary: Optional[str] = None,
        watch: Optional[Union[Literal["watch", "unwatch", "preferences", "nochange"], bool]] = None,
        minor: bool = True,
        botflag: Optional[bool] = None,
        force: bool = False,
        asynchronous: bool = False,
        callback: Any = None,
        apply_cosmetic_changes: Optional[bool] = None,
        quiet: bool = False,
    ) -> None: ...
    def getOldVersion(
        self, oldid: int, force: bool = False, get_redirect: bool = False, sysop: bool = False
    ) -> str: ...
    def properties(self, force: bool = False) -> Dict[str, str]: ...

class User(Page):
    @property
    def username(self) -> str: ...
    def isAnonymous(self) -> bool: ...
    def getUserTalkPage(self) -> Page: ...
    def editCount(self, force: bool = False) -> int: ...

class BaseLink(ComparableMixin): ...

class Link(BaseLink):
    def __init__(self, text: str, source: Optional[Union[Page, pywikibot.site.BaseSite]] = None) -> None: ...
    @property
    def title(self) -> str: ...
    @property
    def namespace(self) -> pywikibot.site.Namespace: ...
    def parse(self) -> None: ...
    def ns_title(self, onsite: Optional[pywikibot.site.BaseSite] = None) -> str: ...

class Revision:
    revid: int
    text: Optional[str]
    timestamp: pywikibot.Timestamp
    user: str
    anon: bool
    comment: str
    minor: bool
    roolbacktoken: str
    _parent_id: Optional[int]
    _content_model: str
    _sha1: str
    @property
    def parent_id(self) -> int: ...
