import hashlib
import os

def safe(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000)
    return salt.hex() + ":" + dk.hex()
