# DURINN_GT id=a09_01_swallow_exception track=sast set=core owasp=A09

def vuln() -> None:
    try:
        1 / 0
    except Exception:
        pass  # BUG: no logging/monitoring
