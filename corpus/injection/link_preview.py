"""Link preview fetcher for the support console."""

import requests
from flask import request


def preview():
    # deadbolt-expect DB-INJ-006:medium
    return requests.get(request.args.get("target"), timeout=5).text
