from urllib.parse import urlparse

ALLOWED = {"example.com"}

def safe(url: str) -> bool:
    p = urlparse(url)
    return (p.hostname or "") in ALLOWED
