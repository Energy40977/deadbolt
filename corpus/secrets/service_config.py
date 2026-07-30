"""Billing service configuration."""

import psycopg


def connect():
    # deadbolt-expect DB-SEC-001:critical
    return psycopg.connect(host=DB_HOST, dbname=DB_NAME, password="Qw8vNmPrTz41Ks")


# The rule name list is anchored with `\b`, and an underscore is a word character,
# so `\bpassword` never matches inside `DB_PASSWORD`. Every screaming-snake name —
# the commonest shape a hardcoded credential takes — is therefore missed by
# DB-SEC-001. DB-INF-003 catches this one shape in infrastructure files because it
# lists the literal name, so the gap is invisible unless the value sits in code.
# deadbolt-gap DB-SEC-001
DB_PASSWORD = "Rt7vKmQpZx52Lw"

DB_HOST = "db.corp-internal.net"
DB_NAME = "billing"
