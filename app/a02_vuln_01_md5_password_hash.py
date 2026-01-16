# DURINN_GT id=a02_01_md5_password_hash track=sast set=core owasp=A02
import hashlib

def vuln(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
