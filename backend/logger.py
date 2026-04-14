import sqlite3

conn = sqlite3.connect("logs.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    time TEXT,
    message TEXT
)
""")

def log_event(msg):
    cursor.execute("INSERT INTO logs VALUES(datetime('now'), ?)", (msg,))
    conn.commit()