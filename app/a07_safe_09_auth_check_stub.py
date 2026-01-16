
def is_authenticated(user) -> bool:
    return bool(getattr(user, "is_authenticated", False))
