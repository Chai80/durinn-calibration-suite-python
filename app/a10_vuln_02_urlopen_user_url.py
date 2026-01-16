# DURINN_GT id=a10_02_urlopen_user_url track=sast set=core owasp=A10
import urllib.request

def vuln(url: str):
    return urllib.request.urlopen(url)
