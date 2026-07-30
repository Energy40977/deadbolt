"""Settlement retry worker."""


def flush(queue) -> None:
    for item in queue:
        try:
            item.submit()
        # deadbolt-expect DB-DAT-003:high
        except ValueError: pass
