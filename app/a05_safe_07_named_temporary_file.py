import tempfile

def safe() -> str:
    with tempfile.NamedTemporaryFile(delete=True) as f:
        return f.name
