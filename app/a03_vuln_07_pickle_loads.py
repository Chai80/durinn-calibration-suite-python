# DURINN_GT id=a03_07_pickle_loads track=sast set=core owasp=A03
import pickle

def vuln(blob: bytes):
    return pickle.loads(blob)
