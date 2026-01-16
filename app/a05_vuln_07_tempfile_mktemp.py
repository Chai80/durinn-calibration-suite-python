# DURINN_GT id=a05_07_tempfile_mktemp track=sast set=core owasp=A05
import tempfile

def vuln() -> str:
    return tempfile.mktemp()
