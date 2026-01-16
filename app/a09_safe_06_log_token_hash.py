import hashlib
import logging

logger = logging.getLogger(__name__)

def safe(token: str) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:8]
    logger.warning("token_hash=%s", token_hash)
