# DURINN_GT id=a09_06_log_auth_token track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)

def vuln(token: str) -> None:
    logger.warning("token=%s", token)
