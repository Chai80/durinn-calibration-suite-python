# DURINN_GT id=a05_06_chmod_777 track=sast set=core owasp=A05
import os

def vuln(path: str) -> None:
    os.chmod(path, 0o777)
