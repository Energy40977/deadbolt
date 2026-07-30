"""Invoice attachment download."""

from flask import request


def attachment_body():
    # deadbolt-expect DB-INJ-004:high
    return open(request.args.get("path")).read()
