# DURINN_GT id=a03_09_file_open_user_input track=sast set=core owasp=A03

def vuln(filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()
