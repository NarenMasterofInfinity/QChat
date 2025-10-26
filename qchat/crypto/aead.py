from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac, hashlib
class AEAD:
    def __init__(self, key: bytes): self.a = AESGCM(key)
    def enc(self, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes: return self.a.encrypt(nonce, plaintext, ad)
    def dec(self, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes: return self.a.decrypt(nonce, ciphertext, ad)
def nonce_from(key: bytes, counter: int, ad: bytes) -> bytes:
    return hmac.new(key, ad + counter.to_bytes(8,'big'), hashlib.sha256).digest()[:12]

