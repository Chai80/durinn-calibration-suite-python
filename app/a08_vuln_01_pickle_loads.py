# DURINN_GT id=a08_01_pickle_loads track=sast set=core owasp=A08
import pickle

def vuln(blob: bytes):
    return pickle.loads(blob)
