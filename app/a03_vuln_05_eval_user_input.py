# DURINN_GT id=a03_05_eval_user_input track=sast set=core owasp=A03

def vuln(expr: str):
    return eval(expr)
