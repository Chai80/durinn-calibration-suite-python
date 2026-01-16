# DURINN_GT id=a04_06_unvalidated_action_dispatch track=sast set=core owasp=A04

def do_admin_action(action: str):
    # BUG: unvalidated action name
    fn = globals().get(action)
    if callable(fn):
        return fn()
    return None
