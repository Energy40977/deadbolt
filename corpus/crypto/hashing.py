"""Integrity digest over a settlement payload."""

import hashlib


def payload_digest(payload: bytes) -> str:
    # deadbolt-expect DB-CRY-002:high
    return hashlib.md5(payload).hexdigest()
