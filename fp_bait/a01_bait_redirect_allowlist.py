from flask import redirect

# Safe: only redirects to known-safe internal paths
ALLOWED = {"/", "/home"}

def safe(next_url: str):
    if next_url not in ALLOWED:
        next_url = "/"
    return redirect(next_url)
