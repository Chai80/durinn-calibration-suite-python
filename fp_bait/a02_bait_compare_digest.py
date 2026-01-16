import hmac

def safe(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
