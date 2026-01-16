# DURINN_GT id=a08_09_subprocess_shell track=sast set=core owasp=A08
import subprocess

def vuln(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=False)
