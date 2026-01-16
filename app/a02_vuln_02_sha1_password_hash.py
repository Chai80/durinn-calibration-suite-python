# DURINN_GT id=a02_02_sha1_password_hash track=sast set=core owasp=A02
import hashlib

def vuln(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()
