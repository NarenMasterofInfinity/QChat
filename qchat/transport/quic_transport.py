import asyncio, ssl, os, pathlib, inspect
from typing import List, Tuple, Any
from ..util_log import log

_CLIENT_CTXS: List[Any] = []
_SERVER_CTXS: List[Any] = []

def _need():
    try:
        import aioquic  # noqa
        from aioquic.asyncio import serve, connect  # noqa
        from aioquic.quic.configuration import QuicConfiguration  # noqa
        return True
    except Exception as e:
        raise RuntimeError("QUIC requested but 'aioquic' is not available") from e

def _cert_paths() -> Tuple[str, str]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    base = pathlib.Path(os.environ.get("QCHAT_HOME") or (pathlib.Path.home()/".qchat"))
    base.mkdir(parents=True, exist_ok=True)
    cert = base/'cert.pem'; key = base/'key.pem'
    if not cert.exists() or not key.exists():
        key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"qchat")])
        cert_obj = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer).public_key(key_obj.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow()-datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=3650))
            .sign(key_obj, hashes.SHA256()))
        cert.write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(key_obj.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return str(cert), str(key)

def _is_async_cm(x: Any) -> bool:
    return hasattr(x, "__aenter__") and hasattr(x, "__aexit__")

async def _maybe_enter(x: Any, keep_list: list) -> Any:
    if _is_async_cm(x):
        log("quic: entering async CM")
        obj = await x.__aenter__()
        keep_list.append(x)
        return obj
    if inspect.isawaitable(x):
        log("quic: awaiting coroutine")
        obj = await x
        keep_list.append(obj)
        return obj
    log("quic: got ready object")
    keep_list.append(x)
    return x

async def start_quic_server(host: str, port: int, handler):
    _need()
    from aioquic.asyncio import serve
    from aioquic.quic.configuration import QuicConfiguration

    cert, key = _cert_paths()
    qc = QuicConfiguration(is_client=False, alpn_protocols=["h3", "hq-29", "hq-32"])
    qc.load_cert_chain(cert, key)

    cm_or_coro = serve(host, port, configuration=qc, stream_handler=handler)
    server = await _maybe_enter(cm_or_coro, _SERVER_CTXS)
    log(f"quic: server ready on {host}:{port}")
    return server

async def open_quic_connection(host: str, port: int):
    _need()
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration

    qc = QuicConfiguration(is_client=True, alpn_protocols=["h3", "hq-29", "hq-32"])
    qc.verify_mode = ssl.CERT_NONE

    cm_or_coro = connect(host, port, configuration=qc)
    client = await _maybe_enter(cm_or_coro, _CLIENT_CTXS)
    log("quic: client connected, creating stream")
    create = client.create_stream()
    if inspect.isawaitable(create):
        reader, writer = await create
    else:
        reader, writer = create
    log("quic: stream ready")
    return reader, writer

async def quic_shutdown():
    for lst in (_CLIENT_CTXS, _SERVER_CTXS):
        while lst:
            cm = lst.pop()
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                pass
    log("quic: shutdown complete")

