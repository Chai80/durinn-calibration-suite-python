# DURINN_GT id=a09_10_ignore_security_check track=sast set=core owasp=A09

def check_mfa(user) -> bool:
    return False

def vuln(user) -> None:
    check_mfa(user)  # BUG: ignore result
    return None
