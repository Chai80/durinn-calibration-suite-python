import logging

logger = logging.getLogger(__name__)

def safe(username: str, password: str) -> None:
    _ = password
    logger.info("login user=%s password=[REDACTED]", username)
