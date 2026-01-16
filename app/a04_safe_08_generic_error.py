
def handle_error() -> str:
    try:
        1 / 0
    except Exception:
        return "internal error"
