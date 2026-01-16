# DURINN_GT id=a02_08_secret_compare_equals track=sast set=core owasp=A02

def vuln(sig: str, expected: str) -> bool:
    return sig == expected
