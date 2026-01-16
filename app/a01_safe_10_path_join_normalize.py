import os

BASE = "/var/app/data"
ALLOWED = {"readme.txt", "about.txt"}

def safe(name: str) -> str:
    if name not in ALLOWED:
        raise ValueError("not allowed")
    p = os.path.join(BASE, name)
    with open(p, "r", encoding="utf-8") as f:
        return f.read()
