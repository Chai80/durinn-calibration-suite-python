# DURINN_GT id=a09_05_log_password track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)

def vuln(username: str, password: str) -> None:
    logger.info("login %s %s", username, password)
