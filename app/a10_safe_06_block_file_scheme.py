from urllib.parse import urlparse

def safe(url: str) -> str:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        return "no"
    return "ok"
