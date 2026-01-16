from pathlib import Path

ALLOWED = {"README.txt", "about.txt"}

def safe(user_path: str) -> str:
    if user_path not in ALLOWED:
        raise ValueError("not allowed")
    return Path(user_path).read_text(encoding="utf-8")
