"""
SECURE (FIXED) VERSION - vulnerable app ki har problem ka remediation.
Har fix ke saath "FIX-xx" comment hai (VULN-xx ke matching).
"""
import ast
import hmac
import ipaddress
import operator
import os
import re
import secrets
import sqlite3
import subprocess
import time
import uuid

from flask import (Flask, abort, jsonify, render_template_string, request,
                   send_from_directory, session)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "secure.db")
UPLOAD_DIR = os.path.join(BASE, "uploads")
FILES_DIR = os.path.join(BASE, "files")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)
with open(os.path.join(FILES_DIR, "readme.txt"), "w") as fh:
    fh.write("Public readme file.\n")

app = Flask(__name__)
# FIX-01: Secret environment variable se (nahi mila to random)
app.config.update(
    SECRET_KEY=os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("APP_HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # FIX-12: 1 MB upload limit
)

ALLOWED_EXT = {"png", "jpg", "jpeg", "txt", "pdf"}
FAILED = {}  # FIX-04: simple in-memory login throttling
MAX_TRIES, LOCK_SECONDS = 5, 60

HOME = """
<h2>Secure Demo App</h2>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/search?q=test">Search</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping tool</a></li>
  <li><a href="/calc?expr=2%2B2">Calculator</a></li>
  <li><a href="/file?name=readme.txt">Download file</a></li>
  <li><a href="/profile/1">Profile (login required)</a></li>
  <li><a href="/upload">Upload</a></li>
</ul>
"""


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    if not hmac.compare_digest(sent, session.get("csrf", "")):
        abort(400, "CSRF check failed")


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
        "password TEXT, role TEXT, email TEXT)"
    )
    seed = [
        ("admin", "admin123", "admin", "admin@example.com"),
        ("alice", "alice123", "user", "alice@example.com"),
        ("bob", "bob123", "user", "bob@example.com"),
    ]
    for u, p, r, e in seed:
        # FIX-02: salted, slow hash (werkzeug scrypt/pbkdf2)
        c.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
            (u, generate_password_hash(p), r, e),
        )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template_string(HOME)


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        check_csrf()
        u = request.form.get("username", "")[:50]
        p = request.form.get("password", "")[:128]
        tries, until = FAILED.get(u, (0, 0))
        if until > time.time():
            msg = "Too many attempts. Try later."
        else:
            # FIX-03: Parameterized query
            row = get_db().execute(
                "SELECT id, username, role, password FROM users WHERE username = ?",
                (u,),
            ).fetchone()
            if row and check_password_hash(row[3], p):
                FAILED.pop(u, None)
                keep = session.get("csrf")
                session.clear()
                session["csrf"] = keep
                session["uid"], session["user"], session["role"] = row[:3]
                msg = "Login successful"
            else:
                tries += 1
                FAILED[u] = (tries, time.time() + LOCK_SECONDS if tries >= MAX_TRIES else 0)
                msg = "Invalid credentials"  # generic message
    # FIX-05: msg ab variable hai, template string ka hissa nahi (autoescaped)
    return render_template_string(
        """<h2>Login</h2><form method="post">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <input name="username" placeholder="username">
        <input name="password" type="password" placeholder="password">
        <button>Login</button></form><p>{{ msg }}</p>""",
        msg=msg,
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")[:100]
    # FIX-06: Jinja autoescape se output encoding
    return render_template_string("<h2>Search results for: {{ q }}</h2>", q=q)


HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX-07: strict validation + list arguments + no shell
    if not HOST_RE.match(host):
        return "Invalid host", 400
    flag = "-n" if os.name == "nt" else "-c"
    try:
        res = subprocess.run(
            ["ping", flag, "1", host], capture_output=True, text=True, timeout=10
        )
        return render_template_string("<pre>{{ out }}</pre>", out=res.stdout or res.stderr)
    except (OSError, subprocess.TimeoutExpired):
        return "Ping failed", 500


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv}


def safe_eval(expr):
    """Sirf numbers aur + - * / allow karta hai."""
    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if (isinstance(node, ast.Constant) and isinstance(node.value, (int, float))
                and not isinstance(node.value, bool)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        raise ValueError("Unsupported expression")
    if len(expr) > 100:
        raise ValueError("Too long")
    return ev(ast.parse(expr, mode="eval"))


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # FIX-08: eval() ki jagah AST-based whitelist evaluator
    try:
        return render_template_string("Result: {{ r }}", r=safe_eval(expr))
    except (ValueError, SyntaxError, ZeroDivisionError):
        return "Invalid expression", 400


@app.route("/file")
def download():
    name = request.args.get("name", "readme.txt")
    # FIX-09: send_from_directory path traversal block karta hai (404)
    return send_from_directory(FILES_DIR, name)


@app.route("/profile/<int:uid>")
def profile(uid):
    # FIX-10: authentication + authorization (sirf apna profile ya admin)
    if "uid" not in session:
        abort(401)
    if session["uid"] != uid and session.get("role") != "admin":
        abort(403)
    row = get_db().execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (uid,)
    ).fetchone()  # FIX-11: password hash return nahi hota
    return jsonify(profile=row) if row else ("Not found", 404)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "uid" not in session:
        abort(401)
    if request.method == "POST":
        check_csrf()
        f = request.files.get("file")
        if not f or not f.filename:
            return "No file", 400
        name = secure_filename(f.filename)
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        # FIX-12: extension allowlist + safe & random filename
        if ext not in ALLOWED_EXT:
            return "File type not allowed", 400
        f.save(os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}.{ext}"))
        return "Uploaded safely"
    return render_template_string(
        """<h2>Upload</h2><form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <input type="file" name="file"><button>Upload</button></form>"""
    )


if __name__ == "__main__":
    init_db()
    # FIX-13: debug OFF
    app.run(host="127.0.0.1", port=5001, debug=False)
