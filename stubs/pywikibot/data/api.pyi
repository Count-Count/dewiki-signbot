from pywikibot.exceptions import Error

class APIError(Error):
    code: str
