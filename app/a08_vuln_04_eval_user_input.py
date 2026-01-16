# DURINN_GT id=a08_04_eval_user_input track=sast set=core owasp=A08

def vuln(expr: str):
    return eval(expr)
