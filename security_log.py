"""Writes security events to a log file."""

import logging

LOG_FILE = "security.log"

logger = logging.getLogger("security")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    logger.addHandler(handler)


def clean(text: str) -> str:
    """Make user-typed text safe for a log line.

    Without this, someone could type a username containing a newline and
    forge fake log entries (this attack is called log injection).
    """
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:50]