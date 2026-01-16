import importlib

ALLOWED = {"math", "json"}

def safe(mod: str):
    if mod not in ALLOWED:
        raise ValueError("not allowed")
    return importlib.import_module(mod)
