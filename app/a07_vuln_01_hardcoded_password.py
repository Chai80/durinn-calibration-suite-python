# DURINN_GT id=a07_01_hardcoded_password track=sast set=core owasp=A07
DB_PASSWORD = "DURINN_TEST_SECRET_DO_NOT_USE"

def connect():
    # pretend to use it
    return f"connecting with {DB_PASSWORD[:3]}***"
