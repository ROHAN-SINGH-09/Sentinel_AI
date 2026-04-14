from flask import Flask, render_template
from flask_socketio import SocketIO
import sqlite3, time

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

def get_logs():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY time DESC LIMIT 50")
    return cursor.fetchall()

@app.route("/")
def home():
    return render_template("index.html")

def stream_logs():
    while True:
        logs = get_logs()
        socketio.emit("logs", {"data": logs})
        time.sleep(2)

if __name__ == "__main__":
    socketio.start_background_task(stream_logs)
    socketio.run(app, debug=True, use_reloader=False)