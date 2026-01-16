# DURINN_GT id=a07_07_weak_token_random track=sast set=core owasp=A07
import random

def make_token() -> str:
    # Predictable token generation
    return str(random.randint(100000, 999999))
