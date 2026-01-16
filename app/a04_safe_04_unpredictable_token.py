import secrets

def make_reset_token(user_id: str) -> str:
    _ = user_id
    return secrets.token_urlsafe(32)
