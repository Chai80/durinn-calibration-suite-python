# DURINN_GT id=a09_07_log_headers track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)

def vuln(headers: dict) -> None:
    logger.info("headers=%s", headers)
