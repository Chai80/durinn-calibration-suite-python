import logging

logger = logging.getLogger(__name__)

def safe() -> bool:
    try:
        raise ValueError("bad")
    except Exception:
        logger.exception("auth error")
        return False
