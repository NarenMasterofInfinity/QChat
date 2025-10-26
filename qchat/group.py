from dataclasses import dataclass, field
from typing import Dict
from .storage import load_groups, save_groups
from .util_log import log
@dataclass
class GroupInfo:
    name: str
    admin: str
    members: Dict[str, dict] = field(default_factory=dict)  # {user: {"approved": bool}}
def _groups() -> Dict[str, GroupInfo]:
    raw = load_groups(); out = {}
    for k,v in raw.items(): out[k]=GroupInfo(name=v['name'], admin=v['admin'], members=v['members'])
    return out
def _save(gs: Dict[str, GroupInfo]):
    raw = {k: {'name':g.name, 'admin':g.admin, 'members':g.members} for k,g in gs.items()} ; save_groups(raw)
def list_groups() -> dict: return load_groups()
def create_group(name: str, admin: str) -> GroupInfo:
    gs=_groups()
    if name in gs: log("group/create: exists", name); return gs[name]
    gi=GroupInfo(name=name, admin=admin, members={admin:{'approved':True}}); gs[name]=gi; _save(gs); log("group/create: ok", name, "admin", admin); return gi
def join_group(name: str, user: str) -> GroupInfo:
    gs=_groups()
    if name not in gs:
        gi=GroupInfo(name=name, admin=user, members={user:{'approved':True}}); gs[name]=gi; log("group/join: created", name, "by", user)
    else:
        gi=gs[name]; gi.members.setdefault(user, {'approved':False}); log("group/join: req", name, user)
    _save(gs); return gi
def approve_member(name: str, by: str, member: str) -> GroupInfo:
    gs=_groups()
    if name not in gs: raise RuntimeError('group not found')
    gi=gs[name]
    if gi.admin!=by: raise RuntimeError('only admin can approve')
    if member not in gi.members: raise RuntimeError('member not in group')
    gi.members[member]['approved']=True; _save(gs); log("group/approve: ok", name, member, "by", by); return gi
def get_group(name: str) -> GroupInfo:
    gs=_groups()
    if name not in gs: raise RuntimeError('group not found')
    return gs[name]

