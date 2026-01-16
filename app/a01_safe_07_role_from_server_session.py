
def is_admin(user) -> bool:
    # safe: server-side role
    return bool(getattr(user, "is_admin", False))
