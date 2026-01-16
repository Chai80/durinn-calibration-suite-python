import re

def safe(s: str) -> bool:
    # Bound input length defensively
    s2 = s[:200]
    return bool(re.match(r"a+$", s2))
