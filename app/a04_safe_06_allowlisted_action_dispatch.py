ALLOWED = {"safe_action"}

def safe_action():
    return "ok"

def do_admin_action(action: str):
    if action not in ALLOWED:
        raise ValueError("not allowed")
    return safe_action()
