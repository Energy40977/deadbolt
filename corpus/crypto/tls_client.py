"""HTTP client for the settlement gateway."""

import requests


def gateway_session() -> requests.Session:
    session = requests.Session()
    # deadbolt-expect DB-CRY-001:critical
    session.verify = False
    return session
