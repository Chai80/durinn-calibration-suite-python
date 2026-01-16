import os

JWT_SECRET = os.environ.get("JWT_SECRET", "")

def safe(payload: str) -> str:
    return payload + "." + (JWT_SECRET or "<missing>")
