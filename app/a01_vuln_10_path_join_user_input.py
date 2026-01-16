# DURINN_GT id=a01_10_path_join_user_input track=sast set=core owasp=A01
import os

BASE = "/var/app/data"

def vuln(name: str) -> str:
    p = os.path.join(BASE, name)
    with open(p, "r", encoding="utf-8") as f:
        return f.read()
