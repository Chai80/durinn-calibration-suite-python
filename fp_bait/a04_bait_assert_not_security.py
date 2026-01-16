# This assert is not used for authorization; it's a developer sanity check.

def safe(x: int) -> int:
    assert x >= 0
    return x
