# DURINN_GT id=a08_03_marshal_loads track=sast set=core owasp=A08
import marshal

def vuln(blob: bytes):
    return marshal.loads(blob)
