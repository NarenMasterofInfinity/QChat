import argparse
import asyncio
import base64
import os
import time
from typing import Iterable, List

import pandas as pd

from qchat.conn import Conn
from qchat.transport.quic_transport import open_quic_connection, quic_shutdown
from qchat.crypto.hkdf import hkdf
from qchat.crypto.aead import AEAD, nonce_from
from qchat.crypto.kem import keygen, encaps, decaps


def _now() -> float:
    """High precision timer in seconds."""
    return time.perf_counter()


def _ts() -> str:
    t = time.localtime()
    return time.strftime("%H:%M:%S", t) + f".{int((time.time() % 1) * 1000):03d}"


def _log(message: str) -> None:
    print(f"[{_ts()}] {message}", flush=True)


def _normalize_host(host: str) -> str:
    """Translate wildcard/listener addresses into a connectable host."""

    if host in {"0.0.0.0", "::", "[::]"}:
        return "127.0.0.1"
    return host


async def _open_conn(host: str, port: int, use_quic: bool, name: str):
    host = _normalize_host(host)
# async def _open_conn(host: str, port: int, use_quic: bool, name: str):
    if use_quic:
        _log(f"opening {name} connection via QUIC")
        return await open_quic_connection(host, port)
    _log(f"opening {name} connection via TCP")
    return await asyncio.open_connection(host, port)


async def _ensure_user(conn: Conn, user: str, password: str, timeout: float) -> None:
    reg_payload = {
        "type": "register",
        "user": user,
        "password": password,
        "sig_pk_b64": base64.b64encode(b"stub-sig").decode(),
        "kem_pk_b64": base64.b64encode(b"stub-kem").decode(),
    }
    try:
        _log(f"register {user}")
        resp = await conn.request(reg_payload, timeout=timeout)
        _log(f"register {user} -> {resp.get('type')}")
    except Exception as exc:  # pragma: no cover - best effort setup
        _log(f"register {user} error (expected if already exists): {exc}")

    _log(f"login {user}")
    login_resp = await conn.request(
        {"type": "login", "user": user, "password": password}, timeout=timeout
    )
    if login_resp.get("type") != "login_ok":
        raise RuntimeError(f"login failed for user {user}: {login_resp}")
    _log(f"login {user} -> ok")


async def _ensure_group(
    admin_conn: Conn,
    member_conn: Conn,
    group: str,
    admin_user: str,
    member_user: str,
    timeout: float,
) -> None:
    _log(f"create_group {group}")
    try:
        await admin_conn.request(
            {"type": "create_group", "group": group, "user": admin_user}, timeout=timeout
        )
    except Exception as exc:
        _log(f"create_group {group} error (ok if already exists): {exc}")

    _log(f"join_group {group} as {member_user}")
    await member_conn.request(
        {"type": "join_group", "group": group, "user": member_user}, timeout=timeout
    )

    _log(f"approve_member {member_user} in {group}")
    try:
        await admin_conn.request(
            {
                "type": "approve_member",
                "group": group,
                "user": admin_user,
                "member": member_user,
            },
            timeout=timeout,
        )
    except Exception as exc:
        _log(f"approve_member pending/failed (continuing): {exc}")

    approved = False
    for attempt in range(40):
        listing = await admin_conn.request({"type": "list_groups"}, timeout=timeout)
        group_info = listing.get("groups", {}).get(group, {})
        members = group_info.get("members", {})
        approved = members.get(member_user, {}).get("approved", False)
        _log(f"approval poll {attempt}: {approved}")
        if approved:
            break
        await asyncio.sleep(0.2)
    if not approved:
        raise RuntimeError(f"member {member_user} not approved in group {group}")


def _parse_sizes(raw: str) -> List[int]:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("expected at least one message size")
    sizes = []
    for part in parts:
        value = int(part)
        if value <= 0:
            raise argparse.ArgumentTypeError("message sizes must be positive")
        sizes.append(value)
    return sizes


async def _prepare_environment(args) -> None:
    reader_admin, writer_admin = await _open_conn(args.host, args.port, args.quic, "setup-admin")
    admin_conn = Conn(reader_admin, writer_admin, "setup-admin")
    await admin_conn.start_reader()

    reader_member, writer_member = await _open_conn(args.host, args.port, args.quic, "setup-member")
    member_conn = Conn(reader_member, writer_member, "setup-member")
    await member_conn.start_reader()

    await _ensure_user(admin_conn, args.alice, args.alice_password, args.timeout)
    await _ensure_user(member_conn, args.bob, args.bob_password, args.timeout)
    await _ensure_group(admin_conn, member_conn, args.group, args.alice, args.bob, args.timeout)

    await admin_conn.close()
    await member_conn.close()


async def _measure_trial(
    trial_index: int,
    args,
    message_sizes: Iterable[int],
    key_material: bytes,
    aead: AEAD,
) -> List[dict]:
    rows: List[dict] = []
    conn_name = f"trial-{trial_index}"

    handshake_start = _now()
    reader, writer = await _open_conn(args.host, args.port, args.quic, conn_name)
    conn = Conn(reader, writer, conn_name)
    await conn.start_reader()

    login_resp = await conn.request(
        {"type": "login", "user": args.alice, "password": args.alice_password},
        timeout=args.timeout,
    )
    handshake_end = _now()
    if login_resp.get("type") != "login_ok":
        raise RuntimeError(f"handshake/login failed: {login_resp}")

    handshake_ms = (handshake_end - handshake_start) * 1000.0
    rows.append(
        {
            "trial": trial_index,
            "metric": "handshake_time",
            "transport": "quic" if args.quic else "tcp",
            "user": args.alice,
            "group": args.group,
            "message_size": pd.NA,
            "kem_suite": pd.NA,
            "value": handshake_ms,
            "unit": "ms",
            "notes": "connection open + login",
        }
    )

    sender_keys = keygen()
    receiver_keys = keygen()
    ct, sender_secret, kem_suite = encaps(receiver_keys.pk)
    receiver_secret, kem_suite_dec = decaps(receiver_keys.sk, ct)
    if sender_secret != receiver_secret:
        raise RuntimeError("KEM shared secrets do not match")
    if kem_suite != kem_suite_dec:
        _log("warning: kem suite mismatch between encaps/decaps")

    rows.append(
        {
            "trial": trial_index,
            "metric": "key_exchange_size",
            "transport": "quic" if args.quic else "tcp",
            "user": args.alice,
            "group": args.group,
            "message_size": pd.NA,
            "kem_suite": kem_suite,
            "value": len(ct),
            "unit": "bytes",
            "notes": "x25519 encapsulated public key",
        }
    )

    for msg_size in message_sizes:
        ad = f"{args.group}|{args.alice}|{msg_size}|{trial_index}".encode()
        counter = (trial_index << 32) | msg_size
        nonce = nonce_from(key_material, counter, ad)
        plaintext = os.urandom(msg_size)
        ciphertext = aead.enc(nonce, plaintext, ad)

        send_start = _now()
        ack = await conn.request(
            {
                "type": "chat",
                "group": args.group,
                "user": args.alice,
                "cipher": ciphertext,
                "ad": ad,
            },
            timeout=args.timeout,
        )
        send_end = _now()
        if ack.get("op") != "chat_ack":
            raise RuntimeError(f"unexpected chat ack response: {ack}")

        rows.append(
            {
                "trial": trial_index,
                "metric": "round_trip_time",
                "transport": "quic" if args.quic else "tcp",
                "user": args.alice,
                "group": args.group,
                "message_size": msg_size,
                "kem_suite": pd.NA,
                "value": (send_end - send_start) * 1000.0,
                "unit": "ms",
                "notes": f"chat ack for {msg_size} bytes",
            }
        )

    await conn.close()
    return rows


async def async_main(args) -> None:
    args.message_sizes = _parse_sizes(args.message_sizes)

    await _prepare_environment(args)

    key_material = hkdf(f"{args.group}|{args.alice}".encode())
    aead = AEAD(key_material)

    all_rows: List[dict] = []
    for trial in range(1, args.trials + 1):
        _log(f"starting trial {trial}")
        trial_rows = await _measure_trial(trial, args, args.message_sizes, key_material, aead)
        all_rows.extend(trial_rows)

    if args.quic:
        await quic_shutdown()

    if not all_rows:
        raise RuntimeError("no measurements captured")

    df = pd.DataFrame(all_rows)
    df.sort_values(["trial", "metric", "message_size"], inplace=True)

    out_path = os.path.abspath(args.out)
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    df.to_csv(out_path, index=False)
    _log(f"saved results to {out_path}")
    print(df.to_string(index=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark QChat handshake, key exchange, and RTT")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1; 0.0.0.0/:: will connect via 127.0.0.1)",
    )
    parser.add_argument("--port", type=int, default=8443, help="Server port (default: 8443)")
    parser.add_argument("--quic", action="store_true", help="Use QUIC transport instead of TCP")
    parser.add_argument("--trials", type=int, default=5, help="Number of measurement trials (default: 5)")
    parser.add_argument(
        "--message-sizes",
        default="16,128,1024,4096,16384",
        help="Comma separated plaintext sizes to benchmark (bytes)",
    )
    parser.add_argument("--alice", default="alice", help="Username for the primary client")
    parser.add_argument("--alice-password", default="alice", help="Password for the primary client")
    parser.add_argument("--bob", default="bob", help="Secondary username for group setup")
    parser.add_argument("--bob-password", default="bob", help="Secondary password for group setup")
    parser.add_argument("--group", default="bench", help="Group name used for chat benchmarking")
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Timeout in seconds for each request/handshake step (default: 8.0)",
    )
    parser.add_argument("--out", default="benchmark_results.csv", help="Path to the CSV output file")

    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
