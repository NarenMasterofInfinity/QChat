from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
@dataclass
class KemKeypair: sk: X25519PrivateKey; pk: X25519PublicKey
def keygen() -> KemKeypair:
    sk = X25519PrivateKey.generate(); return KemKeypair(sk=sk, pk=sk.public_key())
def encaps(pk: X25519PublicKey):
    eph = X25519PrivateKey.generate(); ss = eph.exchange(pk)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qchat-kem").derive(ss)
    ct = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return ct, key, "x25519-hkdf"
def decaps(sk: X25519PrivateKey, ct: bytes):
    peer = X25519PublicKey.from_public_bytes(ct); ss = sk.exchange(peer)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qchat-kem").derive(ss)
    return key, "x25519-hkdf"

