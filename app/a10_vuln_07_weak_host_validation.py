# DURINN_GT id=a10_07_weak_host_validation track=sast set=core owasp=A10
from urllib.parse import urlparse

def vuln(url: str) -> bool:
    p = urlparse(url)
    return "example.com" in (p.hostname or "")
