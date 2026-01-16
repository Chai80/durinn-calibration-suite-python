# DURINN_GT id=a02_05_hardcoded_iv track=sast set=core owasp=A02
IV = b"\x00" * 16

def vuln() -> bytes:
    return IV
