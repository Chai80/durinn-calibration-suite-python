# DURINN_GT id=a07_03_hardcoded_jwt_secret track=sast set=core owasp=A07
JWT_SECRET = "DURINN_TEST_JWT_SECRET_DO_NOT_USE"

def sign(payload: str) -> str:
    # toy signature
    return payload + "." + JWT_SECRET
