"""One-time codes for phone verification."""

import random


def issue_code() -> int:
    # deadbolt-expect DB-CRY-005:high
    otp_code = random.randint(100000, 999999)
    return otp_code
