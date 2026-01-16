# Safe: do not execute dynamic code

def safe(code: str) -> None:
    _ = code  # treat as data
