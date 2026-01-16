import ssl

# Create a context object but never use it to make requests.
ctx = ssl.create_default_context()
