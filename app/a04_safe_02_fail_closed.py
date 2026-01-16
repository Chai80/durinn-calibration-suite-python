
def allow_action(user) -> bool:
    try:
        return bool(getattr(user, "can_act", False))
    except Exception:
        return False
