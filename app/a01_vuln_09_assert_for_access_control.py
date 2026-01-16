# DURINN_GT id=a01_09_assert_for_access_control track=sast set=core owasp=A01

def delete_user(current_user, target_user_id: str) -> None:
    # BUG: asserts may be disabled in optimized mode
    assert current_user.is_admin
    _ = target_user_id
