# DURINN_GT id=a03_01_sqli_concat track=sast set=core owasp=A03
import sqlite3

def vuln(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
