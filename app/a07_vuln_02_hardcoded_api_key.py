# DURINN_GT id=a07_02_hardcoded_api_key track=sast set=core owasp=A07
API_KEY = "DURINN_TEST_API_KEY_DO_NOT_USE"

def call_service():
    return {"Authorization": f"Bearer {API_KEY}"}
