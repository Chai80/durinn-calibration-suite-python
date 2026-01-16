# DURINN_GT id=a10_04_socket_connect_user_host track=sast set=core owasp=A10
import socket

def vuln(host: str, port: int):
    return socket.create_connection((host, port))
