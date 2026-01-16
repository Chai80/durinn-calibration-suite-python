import http.client

ALLOWED_HOSTS = {"example.com"}

def safe(host: str):
    if host not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    c = http.client.HTTPConnection(host)
    c.request("GET", "/")
    return c.getresponse()
