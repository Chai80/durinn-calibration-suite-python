# DURINN_GT id=a03_06_exec_user_input track=sast set=core owasp=A03

def vuln(code: str) -> None:
    exec(code)
