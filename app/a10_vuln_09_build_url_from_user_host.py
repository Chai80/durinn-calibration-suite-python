# DURINN_GT id=a10_09_build_url_from_user_host track=sast set=core owasp=A10

def vuln(host: str) -> str:
    return "http://" + host + "/api"
