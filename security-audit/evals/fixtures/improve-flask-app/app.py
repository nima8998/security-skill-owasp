import base64
import pickle
import sqlite3
import subprocess

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = __import__("os").environ.get("FLASK_SECRET_KEY", "")


def get_db():
    conn = sqlite3.connect("monitor.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (data["username"],)).fetchone()
    conn.close()
    if user is None or not check_password_hash(user["password_hash"], data["password"]):
        return jsonify({"error": "invalid username or password"}), 401
    session["user_id"] = user["id"]
    return jsonify({"ok": True})


@app.route("/ping")
def ping():
    if "user_id" not in session:
        return jsonify({"error": "login required"}), 401
    host = request.args.get("host", "localhost")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return jsonify({"output": output.decode()})


@app.route("/dashboards/import", methods=["POST"])
def import_dashboard():
    if "user_id" not in session:
        return jsonify({"error": "login required"}), 401
    blob = request.get_data()
    dashboard = pickle.loads(base64.b64decode(blob))
    conn = get_db()
    conn.execute(
        "INSERT INTO dashboards (user_id, name, layout) VALUES (?, ?, ?)",
        (session["user_id"], dashboard["name"], str(dashboard["layout"])),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/dashboards")
def list_dashboards():
    if "user_id" not in session:
        return jsonify({"error": "login required"}), 401
    conn = get_db()
    rows = conn.execute("SELECT * FROM dashboards WHERE user_id = ?", (session["user_id"],)).fetchall()
    conn.close()
    result = []
    for r in rows:
        result.append({"id": r["id"], "name": r["name"], "layout": r["layout"]})
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
