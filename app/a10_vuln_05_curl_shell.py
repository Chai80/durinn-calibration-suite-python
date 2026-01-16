# DURINN_GT id=a10_05_curl_shell track=sast set=core owasp=A10
import subprocess

def vuln(url: str) -> None:
    subprocess.run("curl " + url, shell=True, check=False)
