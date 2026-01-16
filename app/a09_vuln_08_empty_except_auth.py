# DURINN_GT id=a09_08_empty_except_auth track=sast set=core owasp=A09

def vuln() -> bool:
    try:
        raise ValueError("bad")
    except:
        return False  # BUG: no monitoring
