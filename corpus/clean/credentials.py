# deadbolt-clean
"""Credential handling: configuration in, bcrypt out."""

import os

import bcrypt

DB_PASSWORD = os.environ["APP_DB_PASSWORD"]


def store(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
