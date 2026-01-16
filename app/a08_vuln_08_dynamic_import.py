# DURINN_GT id=a08_08_dynamic_import track=sast set=core owasp=A08
import importlib

def vuln(mod: str):
    return importlib.import_module(mod)
