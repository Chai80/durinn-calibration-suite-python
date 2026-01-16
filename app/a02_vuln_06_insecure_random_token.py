# DURINN_GT id=a02_06_insecure_random_token track=sast set=core owasp=A02
import random

def vuln() -> str:
    return str(random.randint(100000, 999999))
