from pathlib import Path

ALLOWED = {"README.txt", "about.txt"}

def safe(filename: str) -> str:
    if filename not in ALLOWED:
        raise ValueError("not allowed")
    p = Path(filename)
    return p.read_text(encoding="utf-8")
