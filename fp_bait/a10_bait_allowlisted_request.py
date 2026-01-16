import requests

def safe(url: str):
    # Safe placeholder used for internal-only allowlisted calls.
    return requests.get(url)
