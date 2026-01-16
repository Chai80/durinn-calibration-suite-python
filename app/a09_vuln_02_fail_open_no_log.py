# DURINN_GT id=a09_02_fail_open_no_log track=sast set=core owasp=A09

def vuln() -> bool:
    try:
        raise RuntimeError("boom")
    except Exception:
        return True
