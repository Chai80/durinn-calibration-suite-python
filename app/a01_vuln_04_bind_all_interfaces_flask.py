# DURINN_GT id=a01_04_bind_all_interfaces_flask track=sast set=core owasp=A01
from flask import Flask

app = Flask(__name__)

def vuln():
    # Example only; not executed.
    app.run(host="0.0.0.0", port=5000)
