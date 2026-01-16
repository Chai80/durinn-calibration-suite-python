import os

def safe(path: str) -> None:
    os.chmod(path, 0o600)
