import logging

logger = logging.getLogger(__name__)

def safe():
    try:
        1 / 0
    except Exception:
        logger.exception("error")
