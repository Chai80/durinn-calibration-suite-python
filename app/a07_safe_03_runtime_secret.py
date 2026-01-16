import secrets

JWT_SECRET = secrets.token_urlsafe(32)

def sign(payload: str) -> str:
    return payload + "." + JWT_SECRET
