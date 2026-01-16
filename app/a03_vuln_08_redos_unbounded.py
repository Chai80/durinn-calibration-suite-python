# DURINN_GT id=a03_08_redos_unbounded track=sast set=core owasp=A03
import re

def vuln(s: str) -> bool:
    return bool(re.match(r"(a+)+$", s))
