# DURINN_GT id=a09_09_stacktrace_print track=sast set=core owasp=A09
import traceback

def vuln() -> str:
    try:
        1 / 0
    except Exception:
        return traceback.format_exc()
