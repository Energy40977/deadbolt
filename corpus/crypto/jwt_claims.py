"""Session claim extraction."""

import jwt


def claims_of(raw_token: str) -> dict:
    # deadbolt-expect DB-CRY-007:high
    return jwt.decode(raw_token)
