# DURINN_GT id=a08_10_exec_file_contents track=sast set=core owasp=A08

def vuln(path: str) -> None:
    code = open(path, "r", encoding="utf-8").read()
    exec(code)
