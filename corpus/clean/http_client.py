# deadbolt-clean
"""Outbound calls: https, bounded, verified."""

import requests

SESSION = requests.Session()


def invoice(invoice_id: str) -> dict:
    response = SESSION.get(
        f"https://billing.acme-corp.net/invoices/{invoice_id}", timeout=10
    )
    response.raise_for_status()
    return response.json()
