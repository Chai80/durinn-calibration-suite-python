from pathlib import Path

# Safe: normalizes and enforces base directory
BASE = Path("/var/app/data").resolve()

def safe(user_path: str) -> str:
    p = (BASE / user_path).resolve()
    if not str(p).startswith(str(BASE)):
        raise ValueError("blocked")
    return str(p)
