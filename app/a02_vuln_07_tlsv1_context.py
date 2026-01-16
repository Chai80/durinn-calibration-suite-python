# DURINN_GT id=a02_07_tlsv1_context track=sast set=core owasp=A02
import ssl

def vuln():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
