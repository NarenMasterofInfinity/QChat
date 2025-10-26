# qchat/server.py
from __future__ import annotations
import asyncio, base64, json, traceback, os
from typing import Dict, Optional
from .transport.message import pack, unpack, now_ms, new_msg_id
from .group import create_group, join_group, approve_member as grp_approve, get_group, list_groups as srv_list_groups
from .auth import register as reg_user, verify_login
from .treekem import derive_root, MemberView
from .storage import write_server_log, server_log_path
from .util_log import log

# Toggle audit I/O during benchmarks: export QCHAT_AUDIT=0
QCHAT_AUDIT_ENABLED = os.environ.get("QCHAT_AUDIT", "1") != "0"

def _echo(msg, resp):
    rid = msg.get("rid")
    if isinstance(resp, dict) and rid is not None:
        resp = {**resp, "rid": rid}
    return resp

class HubServer:
    def __init__(self, host: str, port: int, use_quic: bool = False):
        self.host, self.port = host, port
        self.use_quic = use_quic
        self.clients: Dict[asyncio.StreamWriter, str] = {}
        self.group_roots: Dict[str, bytes] = {}
        self.server = None

    async def start(self):
        if self.use_quic:
            from .transport.quic_transport import start_quic_server
            # aioquic may call the handler without awaiting; return a Task
            def handler(reader, writer):
                log("server/stream: new stream")
                return asyncio.create_task(self._handle(reader, writer))
            self.server = await start_quic_server(self.host, self.port, handler)
            log(f"[Server] QUIC listening on {self.host}:{self.port}")
        else:
            self.server = await asyncio.start_server(self._handle, self.host, self.port)
            log(f"[Server] TCP listening on {self.host}:{self.port}")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        log("server/_handle: start")
        try:
            while True:
                size_b = await reader.readexactly(4)
                size = int.from_bytes(size_b, "big")
                data = await reader.readexactly(size)
                msg = unpack(data)
                log("server/recv:", msg.get("type"), "rid", msg.get("rid"), "user", msg.get("user"), "group", msg.get("group"))
                await self._safe_route(msg, writer)
        except asyncio.IncompleteReadError:
            log("server/_handle: client closed")
        except Exception as e:
            log("server/_handle: error", e)
        finally:
            self.clients.pop(writer, None)
            try:
                writer.close()
            except Exception:
                pass

    async def _send_reply(self, w, d: dict):
        b = pack(d)
        w.write(len(b).to_bytes(4, "big") + b)
        try:
            await w.drain()
            log("server/reply:", d.get("type"), "rid", d.get("rid"))
        except Exception as e:
            log("server/reply-error:", e)

    async def _send_push(self, w, d: dict):
        b = pack(d)
        w.write(len(b).to_bytes(4, "big") + b)
        try:
            await w.drain()
            log("server/push:", d.get("type"))
        except Exception as e:
            log("server/push-error:", e)

    async def _broadcast_group(self, group: str, d: dict):
        gi = get_group(group)
        for w, u in list(self.clients.items()):
            if gi.members.get(u, {}).get("approved", False):
                await self._send_push(w, d)

    async def _audit(self, kind: str, payload: dict, group: Optional[str] = None, audience: Optional[str] = None):
        if not QCHAT_AUDIT_ENABLED:
            return
        evt = {"type": "audit", "kind": kind, "payload": payload, "t_srv": now_ms()}
        write_server_log(evt)
        if group:
            await self._broadcast_group(group, evt)
        elif audience:
            for w, u in list(self.clients.items()):
                if u == audience:
                    await self._send_push(w, evt)

    async def _safe_route(self, m: dict, w):
        try:
            await self._route(m, w)
        except Exception as e:
            if QCHAT_AUDIT_ENABLED:
                write_server_log({"type": "server_error", "err": str(e), "trace": traceback.format_exc(), "t_srv": now_ms()})
            log("server/route-error:", e)
            await self._send_reply(w, _echo(m, {"type": "error", "reason": str(e)}))

    async def _route(self, m: dict, w):
        t = m.get("type")

        if t == "register":
            ok = reg_user(m["user"], m["password"], base64.b64decode(m["sig_pk_b64"]), base64.b64decode(m["kem_pk_b64"]))
            await self._send_reply(w, _echo(m, {"type": "register_ok" if ok == "ok" else "register_fail", "reason": "" if ok == "ok" else "exists"}))
            asyncio.create_task(self._audit("register", {"user": m["user"], "status": ok}))
            return

        if t == "login":
            if verify_login(m["user"], m["password"]):
                self.clients[w] = m["user"]
                await self._send_reply(w, _echo(m, {"type": "login_ok", "user": m["user"]}))
                asyncio.create_task(self._audit("login_ok", {"user": m["user"]}, audience=m["user"]))
            else:
                await self._send_reply(w, _echo(m, {"type": "login_fail"}))
                asyncio.create_task(self._audit("login_fail", {"user": m["user"]}, audience=m["user"]))
            return

        if t == "create_group":
            gi = create_group(m["group"], m["user"])
            await self._send_reply(w, _echo(m, {"type": "ok", "op": "create_group"}))
            asyncio.create_task(self._audit("group_created", {"group": gi.name, "admin": gi.admin}, group=gi.name))
            return

        if t == "join_group":
            gi = join_group(m["group"], m["user"])
            await self._send_reply(w, _echo(m, {"type": "ok", "op": "join_group"}))
            asyncio.create_task(self._audit("join_requested", {"group": gi.name, "user": m["user"]}, group=gi.name))
            return

        if t == "approve_member":
            log("server/approve: enter", m.get("group"), m.get("member"), "by", m.get("user"))
            try:
                gi = grp_approve(m["group"], m["user"], m["member"])
                log("server/approve: primary OK")
            except Exception as e:
                log("server/approve: primary FAIL", repr(e))
                gi = get_group(m["group"])
                memb = gi.members.get(m["member"])
                if memb is None:
                    raise RuntimeError(f"member '{m['member']}' not found in group '{m['group']}'")
                memb["approved"] = True
                from .group import _save, _groups
                gs = _groups()
                gs[gi.name] = gi
                _save(gs)
                log("server/approve: fallback persisted")
            try:
                root = derive_root(gi.name, {k: MemberView(approved=v.get("approved", False)) for k, v in gi.members.items()})
                self.group_roots[gi.name] = root
                log("server/approve: treekem root updated", gi.name, len(root))
            except Exception as e:
                log("server/approve: treekem FAILED", repr(e))
            await self._send_reply(w, _echo(m, {"type": "ok", "op": "approve_member"}))
            log("server/approve: replied")
            asyncio.create_task(self._audit("member_approved", {"group": gi.name, "member": m["member"], "by": m["user"]}, group=gi.name))
            asyncio.create_task(self._broadcast_group(gi.name, {"type": "group_update", "group": gi.name, "epoch": now_ms()}))
            log("server/approve: broadcasts scheduled")
            return

        if t == "list_groups":
            await self._send_reply(w, _echo(m, {"type": "groups", "groups": srv_list_groups()}))
            return

        if t == "pending_for_admin":
            out = {}
            allg = srv_list_groups()
            for gname, g in allg.items():
                if g["admin"] == m["user"]:
                    pend = [u for u, info in g["members"].items() if not info.get("approved", False)]
                    if pend:
                        out[gname] = pend
            await self._send_reply(w, _echo(m, {"type": "pending", "pending": out}))
            return

        if t == "chat":
            # Immediate ACK path for accurate RTT measurement
            msg_id = new_msg_id()
            t_rcv = now_ms()
            m["msg_id"] = msg_id
            m["t_srv_rcv"] = t_rcv

            await self._send_reply(w, _echo(m, {
                "type": "ok",
                "op": "chat_ack",
                "msg_id": msg_id,
                "t_srv_rcv": t_rcv
            }))

            # Broadcast and audit off the critical path
            asyncio.create_task(self._broadcast_group(m["group"], m))
            asyncio.create_task(self._audit("chat_sent", {
                "group": m["group"], "from": m["user"],
                "msg_id": msg_id, "has_file": "file" in m
            }, group=m["group"]))
            return

        if t == "get_events":
            limit = int(m.get("limit", 200))
            group = m.get("group")
            user = m.get("user_filter")
            kind = m.get("kind")
            items = []
            try:
                with open(server_log_path(), "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            evt = json.loads(line)
                        except Exception:
                            continue
                        ok = True
                        if kind and evt.get("kind") != kind: ok = False
                        if group and (evt.get("payload", {}).get("group") != group): ok = False
                        if user and (evt.get("payload", {}).get("user") != user and evt.get("payload", {}).get("from") != user): ok = False
                        if ok:
                            items.append(evt)
                items = items[-limit:]
            except FileNotFoundError:
                items = []
            await self._send_reply(w, _echo(m, {"type": "events", "items": items}))
            return

        await self._send_reply(w, _echo(m, {"type": "error", "reason": f"unknown type {t}"}))
