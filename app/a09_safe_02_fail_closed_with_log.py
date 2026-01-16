import logging

logger = logging.getLogger(__name__)

def safe() -> bool:
    try:
        raise RuntimeError("boom")
    except Exception:
        logger.exception("blocked")
        return False
