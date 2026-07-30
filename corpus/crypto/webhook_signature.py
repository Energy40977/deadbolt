"""Inbound webhook authentication."""


def accept(signature: str, provided: str) -> bool:
    # deadbolt-expect DB-CRY-008:medium
    if signature == provided:
        return True
    return False
