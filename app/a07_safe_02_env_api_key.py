import os

API_KEY = os.environ.get("API_KEY", "")

def call_service():
    return {"Authorization": "Bearer ***"} if API_KEY else {}
