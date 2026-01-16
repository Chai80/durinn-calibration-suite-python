import logging

logger = logging.getLogger(__name__)

def safe(username: str, password: str) -> None:
    _ = password
    logger.info("login %s [REDACTED]", username)
