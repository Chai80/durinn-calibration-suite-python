# DURINN_GT id=a01_02_path_traversal_open track=sast set=core owasp=A01

def vuln(user_path: str) -> str:
    with open(user_path, "r", encoding="utf-8") as f:
        return f.read()
