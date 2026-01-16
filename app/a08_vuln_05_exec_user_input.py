# DURINN_GT id=a08_05_exec_user_input track=sast set=core owasp=A08

def vuln(code: str) -> None:
    exec(code)
