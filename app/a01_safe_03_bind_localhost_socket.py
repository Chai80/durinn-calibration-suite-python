import socket

def safe(port: int = 8080) -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", port))
