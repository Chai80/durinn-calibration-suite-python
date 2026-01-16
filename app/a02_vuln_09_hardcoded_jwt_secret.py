# DURINN_GT id=a02_09_hardcoded_jwt_secret track=sast set=core owasp=A02
JWT_SECRET = "DURINN_TEST_JWT_SECRET_DO_NOT_USE"

def vuln(payload: str) -> str:
    return payload + "." + JWT_SECRET
