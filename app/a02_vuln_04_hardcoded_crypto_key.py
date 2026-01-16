# DURINN_GT id=a02_04_hardcoded_crypto_key track=sast set=core owasp=A02
KEY = b"DURINN_TEST_KEY_16BYTES"  # hardcoded key

def vuln(data: bytes) -> bytes:
    # toy XOR "encryption" (pattern is the hardcoded key)
    return bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])
