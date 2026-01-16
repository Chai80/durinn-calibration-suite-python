import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com"}

def safe(url: str):
    p = urlparse(url)
    if p.hostname not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return requests.get(url, allow_redirects=False)
