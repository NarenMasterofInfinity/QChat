import base64, bcrypt
from .storage import load_users, save_users
from .util_log import log
def register(user: str, password: str, sig_pk: bytes, kem_pk: bytes):
    users = load_users()
    if user in users:
        log("auth/register: exists", user); return "exists"
    ph = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[user] = {"pw": ph, "sig_pk": base64.b64encode(sig_pk).decode(), "kem_pk": base64.b64encode(kem_pk).decode()}
    save_users(users); log("auth/register: ok", user); return "ok"
def verify_login(user: str, password: str) -> bool:
    users = load_users()
    if user not in users: log("auth/login: missing", user); return False
    try:
        ok = bcrypt.checkpw(password.encode(), users[user]["pw"].encode())
        log("auth/login:", user, "ok" if ok else "fail"); return ok
    except Exception as e:
        log("auth/login: error", user, e); return False

