import yaml

def safe(text: str):
    return yaml.safe_load(text)
