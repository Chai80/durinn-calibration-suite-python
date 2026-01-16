import logging

logger = logging.getLogger(__name__)

def safe(headers: dict) -> None:
    h = dict(headers)
    if "Authorization" in h:
        h["Authorization"] = "[REDACTED]"
    logger.info("headers=%s", h)
