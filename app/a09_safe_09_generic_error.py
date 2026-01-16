
def safe() -> str:
    try:
        1 / 0
    except Exception:
        return "internal error"
