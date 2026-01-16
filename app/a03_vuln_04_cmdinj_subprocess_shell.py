# DURINN_GT id=a03_04_cmdinj_subprocess_shell track=sast set=core owasp=A03
import subprocess

def vuln(host: str) -> None:
    subprocess.run("ping -c 1 " + host, shell=True, check=False)
