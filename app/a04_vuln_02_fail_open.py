# DURINN_GT id=a04_02_fail_open track=sast set=core owasp=A04

def allow_action(user) -> bool:
    try:
        return bool(getattr(user, "can_act", False))
    except Exception:
        return True
