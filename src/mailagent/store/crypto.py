import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TokenCipher:
    """AES-256-GCM. Формат: nonce(12) + шифртекст с тегом. aad привязывает токен к строке БД."""

    def __init__(self, key_b64: str):
        key = base64.b64decode(key_b64, validate=True)
        if len(key) != 32:
            raise ValueError("TOKEN_ENCRYPTION_KEY: нужно 32 байта в base64")
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, plaintext.encode(), aad.encode())

    def decrypt(self, blob: bytes, aad: str) -> str:
        return self._aes.decrypt(blob[:12], blob[12:], aad.encode()).decode()


def generate_key() -> str:
    return base64.b64encode(AESGCM.generate_key(256)).decode()
