# deadbolt-clean
"""Certificate verification left on."""

import requests


def session() -> requests.Session:
    session = requests.Session()
    session.verify = True
    return session
