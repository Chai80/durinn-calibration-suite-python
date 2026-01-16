import hashlib

def safe(file_bytes: bytes) -> str:
    # Not a password hash; used for integrity checking.
    return hashlib.sha256(file_bytes).hexdigest()
