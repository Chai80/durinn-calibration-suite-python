# DURINN_GT id=a01_08_fail_open_authz track=sast set=core owasp=A01

def has_access(user, resource) -> bool:
    try:
        return bool(user and resource and user.id == resource.owner_id)
    except Exception:
        return True  # BUG: fail open
