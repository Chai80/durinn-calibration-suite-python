# DURINN_GT id=a04_08_stacktrace_to_user track=sast set=core owasp=A04
import traceback

def handle_error() -> str:
    try:
        1 / 0
    except Exception:
        return traceback.format_exc()  # BUG: leak details
