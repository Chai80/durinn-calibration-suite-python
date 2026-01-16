ALLOWED_HOSTS = {"example.com"}

def safe(host: str) -> str:
    if host not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return "http://" + host + "/api"
