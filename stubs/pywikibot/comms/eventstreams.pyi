from typing import Optional, Iterator
import pywikibot

def site_rc_listener(
    site: pywikibot.site.BaseSite, total: Optional[int] = None
) -> Iterator[pywikibot.mypy.RecentChangesInfo]: ...
