# DURINN_GT id=a10_01_requests_get_user_url track=sast set=core owasp=A10
import requests

def vuln(url: str):
    return requests.get(url)
