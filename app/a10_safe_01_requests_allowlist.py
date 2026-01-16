import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com"}

def safe(url: str):
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        raise ValueError("bad scheme")
    if p.hostname not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return requests.get(url)
