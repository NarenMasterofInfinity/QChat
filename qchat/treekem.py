from dataclasses import dataclass
from .util_log import log
@dataclass
class MemberView: approved: bool
def derive_root(group_name: str, views: dict) -> bytes:
    s = group_name + ":" + ",".join(sorted([f"{u}:{int(v.approved)}" for u,v in views.items()]))
    key = s.encode("utf-8")
    log("treekem/derive_root:", group_name, "len", len(key))
    return key

