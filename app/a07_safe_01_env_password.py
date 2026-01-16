import os

DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

def connect():
    return "connecting" if DB_PASSWORD else "no password set"
