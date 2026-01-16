# DURINN_GT id=a07_09_auth_bypass_stub track=sast set=core owasp=A07
# NOTE: This is intentionally simplistic to create a detectable pattern.

def is_authenticated(user) -> bool:
    return True  # auth bypass
