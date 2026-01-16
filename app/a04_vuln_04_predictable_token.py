# DURINN_GT id=a04_04_predictable_token track=sast set=core owasp=A04
import time

def make_reset_token(user_id: str) -> str:
    # BUG: predictable token
    return f"{user_id}:{int(time.time())}"
