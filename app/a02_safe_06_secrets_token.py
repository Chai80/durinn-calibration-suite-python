import secrets

def safe() -> str:
    return secrets.token_hex(16)
