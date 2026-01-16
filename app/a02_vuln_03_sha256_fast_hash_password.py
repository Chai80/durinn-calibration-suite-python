# DURINN_GT id=a02_03_sha256_fast_hash_password track=sast set=core owasp=A02
import hashlib

def vuln(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
