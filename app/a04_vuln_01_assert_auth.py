# DURINN_GT id=a04_01_assert_auth track=sast set=core owasp=A04

def can_delete(user) -> bool:
    assert user is not None  # BUG: asserts can be stripped
    return True
