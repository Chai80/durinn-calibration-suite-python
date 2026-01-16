from urllib.parse import urlparse

def safe(url: str) -> str:
    # Safe: parses hostname, doesn't fetch.
    p = urlparse(url)
    return p.hostname or ""
