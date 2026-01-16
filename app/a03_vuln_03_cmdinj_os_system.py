# DURINN_GT id=a03_03_cmdinj_os_system track=sast set=core owasp=A03
import os

def vuln(host: str) -> None:
    os.system("ping -c 1 " + host)
