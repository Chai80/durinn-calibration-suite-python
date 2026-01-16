import json

def safe(text: str):
    return json.loads(text)
