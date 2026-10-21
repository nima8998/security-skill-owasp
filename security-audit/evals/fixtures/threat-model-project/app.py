"""Multi-tenant project tracker (JSON API)."""
import functools
import io
import contextlib
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("tracker.db")
        g.db.row_factory = sqlite3.Row
    return g.db


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    row = get_db().execute(
        "SELECT u.id, u.tenant_id, u.is_admin FROM users u JOIN api_tokens t ON t.user_id = u.id WHERE t.token = ?",
        (token,),
    ).fetchone()
    return row


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        g.user = current_user()
        if g.user is None:
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.user["is_admin"]:
            return jsonify({"error": "forbidden"}), 403
        return view(*args, **kwargs)

    return wrapper


@app.get("/api/projects")
@login_required
def list_projects():
    rows = get_db().execute("SELECT id, name FROM projects WHERE tenant_id = ?", (g.user["tenant_id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/projects/<int:project_id>")
@login_required
def get_project(project_id):
    row = get_db().execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.post("/admin/console")
@admin_required
def admin_console():
    """Operator console: runs maintenance snippets (see SECURITY.md)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(request.get_json()["code"], {"db": get_db()})
    return jsonify({"output": out.getvalue()})


if __name__ == "__main__":
    app.run(port=8000)
