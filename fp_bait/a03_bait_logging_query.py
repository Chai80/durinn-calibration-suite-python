import sqlite3

def safe(user_input: str) -> None:
    query = "SELECT * FROM users WHERE name = ?"
    print("running query:", query, "with", user_input)  # logging only
    conn = sqlite3.connect(":memory:")
    conn.execute(query, (user_input,))
