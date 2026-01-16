# DURINN_GT id=a05_08_jinja_autoescape_false track=sast set=core owasp=A05
from jinja2 import Environment

def vuln():
    return Environment(autoescape=False)
