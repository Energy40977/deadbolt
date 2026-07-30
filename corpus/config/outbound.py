"""Currency rate lookup."""

import requests


def rates(url: str) -> dict:
    # deadbolt-expect DB-CFG-004:low
    return requests.get(url).json()
