# DURINN_GT id=a10_10_requests_redirects track=sast set=core owasp=A10
import requests

def vuln(url: str):
    return requests.get(url, allow_redirects=True)
