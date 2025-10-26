from dataclasses import dataclass
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

@dataclass
class SigKeypair:
    sk: bytes
    pk: bytes
    alg: str = "dilithium2"

def keygen() -> SigKeypair:
    public_key, secret_key = generate_keypair()
    return SigKeypair(sk=secret_key, pk=public_key)

def sign_msg(sk: bytes, msg: bytes, alg: str) -> bytes:
    return sign(msg, sk)

def verify_sig(pk: bytes, msg: bytes, sig: bytes, alg: str) -> bool:
    try:
        verify(sig, msg, pk)
        return True
    except Exception:
        return False