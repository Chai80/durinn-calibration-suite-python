# DURINN_GT id=a03_02_sqli_fstring track=sast set=core owasp=A03
import sqlite3

def vuln(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
