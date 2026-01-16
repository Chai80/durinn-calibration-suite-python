import os

def safe() -> bytes:
    return os.urandom(16)
