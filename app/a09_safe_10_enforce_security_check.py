
def check_mfa(user) -> bool:
    return bool(getattr(user, "mfa_ok", False))

def safe(user) -> None:
    if not check_mfa(user):
        raise PermissionError("mfa required")
