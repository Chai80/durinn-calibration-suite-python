# DURINN_GT id=a01_03_bind_all_interfaces_socket track=sast set=core owasp=A01
import socket

def vuln(port: int = 8080) -> None:
    s = socket.socket()
    s.bind(("0.0.0.0", port))
