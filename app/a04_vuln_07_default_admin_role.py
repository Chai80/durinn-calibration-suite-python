# DURINN_GT id=a04_07_default_admin_role track=sast set=core owasp=A04

def new_user_role() -> str:
    # BUG: overly permissive default
    return "admin"
