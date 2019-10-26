from typing import Iterable, Iterator, Any, Optional, Union, List
import datetime
import pywikibot
from pywikibot.tools import UnicodeMixin, ComparableMixin

class PageInUse(pywikibot.Error): ...

class BaseSite:
    def _simple_request(self, **kwargs: Any) -> Any: ...
    def loadrevisions(
        self,
        page: pywikibot.Page,
        content: bool = False,
        revids: Optional[Union[int, str, List[int], List[str]]] = None,
        startid: Optional[int] = None,
        endid: Optional[int] = None,
        starttime: Optional[datetime.datetime] = None,
        endtime: Optional[datetime.datetime] = None,
        rvdir: Optional[bool] = None,
        user: Optional[str] = None,
        excludeuser: Optional[str] = None,
        section: Optional[int] = None,
        sysop: bool = False,
        step: Optional[int] = None,
        total: Optional[int] = None,
        rollback: bool = False,
    ) -> None: ...

class Namespace(Iterable["Namespace"], ComparableMixin, UnicodeMixin):
    MEDIA = -2
    SPECIAL = -1
    MAIN = 0
    TALK = 1
    USER = 2
    USER_TALK = 3
    PROJECT = 4
    PROJECT_TALK = 5
    FILE = 6
    FILE_TALK = 7
    MEDIAWIKI = 8
    MEDIAWIKI_TALK = 9
    TEMPLATE = 10
    TEMPLATE_TALK = 11
    HELP = 12
    HELP_TALK = 13
    CATEGORY = 14
    CATEGORY_TALK = 15
    id: int
    def __iter__(self) -> Iterator["Namespace"]: ...
