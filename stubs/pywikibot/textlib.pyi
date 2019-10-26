from typing import Optional, Any
import pywikibot

def removeDisabledParts(
    text: str, tags: Optional[Any] = None, include: Any = [], site: Optional[pywikibot.site.BaseSite] = None
) -> str: ...

