# DURINN_GT id=a09_04_logger_disabled track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)
logger.disabled = True
