
def has_access(user, resource) -> bool:
    try:
        return bool(user and resource and user.id == resource.owner_id)
    except Exception:
        return False
