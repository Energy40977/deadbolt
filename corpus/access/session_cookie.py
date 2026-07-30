"""Session cookie issuance."""


def issue(response, sid: str):
    # deadbolt-expect DB-AUN-002:medium
    response.set_cookie("sid", sid, httponly=False)
    return response
