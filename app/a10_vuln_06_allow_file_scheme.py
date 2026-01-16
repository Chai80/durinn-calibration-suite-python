# DURINN_GT id=a10_06_allow_file_scheme track=sast set=core owasp=A10
from urllib.parse import urlparse

def vuln(url: str) -> str:
    p = urlparse(url)
    if p.scheme in {"http", "https", "file"}:
        return "ok"
    return "no"
