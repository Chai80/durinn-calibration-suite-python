import ssl
import urllib.request

ctx = ssl.create_default_context()
urllib.request.urlopen("https://example.com", context=ctx)
