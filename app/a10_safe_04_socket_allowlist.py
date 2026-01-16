import socket

ALLOWED_HOSTS = {"example.com"}

def safe(host: str, port: int):
    if host not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return socket.create_connection((host, port))
