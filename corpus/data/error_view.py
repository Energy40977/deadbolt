"""Error envelope for the payments API."""

from flask import jsonify


def failure(e: Exception):
    # deadbolt-expect DB-DAT-002:medium
    return jsonify({"error": str(e)}), 500
