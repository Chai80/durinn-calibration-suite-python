import hmac

def safe(sig: str, expected: str) -> bool:
    return hmac.compare_digest(sig, expected)
