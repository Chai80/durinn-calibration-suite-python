from jinja2 import Environment

def safe():
    return Environment(autoescape=True)
