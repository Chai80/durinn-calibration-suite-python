# DURINN_GT id=a08_02_yaml_load track=sast set=core owasp=A08
import yaml

def vuln(text: str):
    return yaml.load(text, Loader=yaml.Loader)
