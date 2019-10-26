from typing import Union, Optional, Literal, Any, Dict, TypedDict

_Revision = TypedDict("_Revision", {"old": int, "new": int}, total=False)
_Length = TypedDict("_Length", {"old": int, "new": int}, total=False)

RecentChangesInfo = TypedDict(
    "RecentChangesInfo",
    {
        "namespace": int,
        "$schema": str,
        "meta": Any,
        "id": Optional[int],
        "type": Literal["edit", "new", "log", "categorize", "external"],
        "title": str,
        "namespace": int,
        "comment": str,
        "parsedcomment": str,
        "timestamp": int,
        "user": str,
        "bot": bool,
        "server_url": str,
        "server_name": str,
        "server_script_path": str,
        "wiki": str,
        "minor": bool,
        "patrolled": bool,
        "length": _Length,
        "revision": _Revision,
        "log_id": int,
        "log_xtype": str,
        "log_action": str,
        "log_params": Any,
        "log_action_comment": str,
    },
    total=False,
)
