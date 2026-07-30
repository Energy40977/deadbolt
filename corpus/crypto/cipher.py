"""Card token encryption."""

from Crypto.Cipher import AES


def encrypt_token(key: bytes, blob: bytes) -> bytes:
    # deadbolt-expect DB-CRY-003:high
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(blob)
