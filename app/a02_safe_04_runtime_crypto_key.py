import os

KEY = os.urandom(32)

def safe(data: bytes) -> bytes:
    return bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])
