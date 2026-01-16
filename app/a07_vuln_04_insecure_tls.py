# DURINN_GT id=a07_04_insecure_tls track=sast set=core owasp=A07
import ssl
import urllib.request

ctx = ssl._create_unverified_context()
urllib.request.urlopen("https://example.com", context=ctx)
