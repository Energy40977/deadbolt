"""Charge auditing."""

import logging

logger = logging.getLogger(__name__)


def record(card_number: str) -> None:
    # deadbolt-expect DB-DAT-001:high
    logger.info("charge accepted for card %s", card_number)
