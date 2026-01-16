from flask import redirect, request

ALLOWED = {"/", "/home", "/dashboard"}

def safe():
    next_url = request.args.get("next", "/")
    if next_url not in ALLOWED:
        next_url = "/"
    return redirect(next_url)
