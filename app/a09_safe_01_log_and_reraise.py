import logging

logger = logging.getLogger(__name__)

def safe() -> None:
    try:
        1 / 0
    except Exception as e:
        logger.exception("error")
        raise e
