# DURINN_GT id=a01_07_role_from_header track=sast set=core owasp=A01

def is_admin(headers: dict) -> bool:
    # BUG: trust client-controlled header
    return headers.get("X-Role") == "admin"
