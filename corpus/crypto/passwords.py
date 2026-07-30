"""Account credential storage."""

import hashlib


def store_credential(password: str) -> str:
    # deadbolt-expect DB-CRY-004:critical
    return hashlib.sha256(password.encode()).hexdigest()
