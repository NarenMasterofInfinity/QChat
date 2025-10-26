import os, json, pathlib, threading, time
_QHOME = os.environ.get("QCHAT_HOME") or os.path.join(os.path.expanduser("~"), ".qchat")
_SERVER = os.path.join(_QHOME, "server")
_LOGS = os.path.join(_SERVER, "logs")
_USERS = os.path.join(_SERVER, "users.json")
_GROUPS = os.path.join(_SERVER, "groups.json")
_lock = threading.Lock()
def _mk():
    pathlib.Path(_LOGS).mkdir(parents=True, exist_ok=True)
    if not os.path.exists(_USERS): open(_USERS,"w").write("{}")
    if not os.path.exists(_GROUPS): open(_GROUPS,"w").write("{}")
def server_log_path():
    _mk(); day = time.strftime("%Y%m%d"); return os.path.join(_LOGS, f"events-{day}.jsonl")
def write_server_log(evt: dict):
    _mk()
    with _lock: open(server_log_path(), "a", encoding="utf-8").write(json.dumps(evt, ensure_ascii=False)+"\n")
def load_users():
    _mk()
    with _lock: return json.load(open(_USERS,"r",encoding="utf-8"))
def save_users(d: dict):
    _mk()
    with _lock: json.dump(d, open(_USERS,"w",encoding="utf-8"))
def load_groups():
    _mk()
    with _lock: return json.load(open(_GROUPS,"r",encoding="utf-8"))
def save_groups(d: dict):
    _mk()
    with _lock: json.dump(d, open(_GROUPS,"w",encoding="utf-8"))

