import pytest
from cryptography.exceptions import InvalidTag

from mailagent.store.crypto import TokenCipher, generate_key


def test_roundtrip_and_aad_binding():
    c = TokenCipher(generate_key())
    blob = c.encrypt("secret-token", "account:1")
    assert b"secret-token" not in blob
    assert c.decrypt(blob, "account:1") == "secret-token"
    with pytest.raises(InvalidTag):
        c.decrypt(blob, "account:2")  # токен нельзя подсунуть другой строке


def test_nonce_unique_and_bad_key():
    c = TokenCipher(generate_key())
    assert c.encrypt("x", "a") != c.encrypt("x", "a")
    with pytest.raises(ValueError):
        TokenCipher("AAAA")
