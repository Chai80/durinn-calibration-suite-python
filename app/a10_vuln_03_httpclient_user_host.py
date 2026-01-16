# DURINN_GT id=a10_03_httpclient_user_host track=sast set=core owasp=A10
import http.client

def vuln(host: str):
    c = http.client.HTTPConnection(host)
    c.request("GET", "/")
    return c.getresponse()
