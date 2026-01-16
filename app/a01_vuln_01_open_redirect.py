# DURINN_GT id=a01_01_open_redirect track=sast set=core owasp=A01
from flask import redirect, request

def vuln():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
