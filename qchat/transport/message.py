# qchat/transport/message.py
import msgpack, time, secrets

def pack(obj: dict) -> bytes:
    # Compact binary codec; bytes stay bytes (no base64 inflation)
    return msgpack.packb(obj, use_bin_type=True)

def unpack(b: bytes) -> dict:
    # raw=False => msgpack returns str for text, bytes for bin
    return msgpack.unpackb(b, raw=False)

def now_ms() -> int:
    return int(time.time() * 1000)

def new_msg_id() -> str:
    return secrets.token_hex(8)
