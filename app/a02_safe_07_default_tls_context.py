import ssl

def safe():
    return ssl.create_default_context()
