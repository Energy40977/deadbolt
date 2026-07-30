"""Session restore from the cache tier."""

import pickle


def restore(blob: bytes):
    # deadbolt-expect DB-INJ-003:high
    return pickle.loads(blob)
