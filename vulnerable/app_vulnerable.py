"""
!!! INTENTIONALLY VULNERABLE FLASK APP - SIRF LEARNING KE LIYE !!!
- Sirf apni local machine (127.0.0.1) par chalayein.
- Kabhi internet par deploy na karein.
Har vulnerability ke saath "VULN-xx" comment hai taake report mein map ho sake.
"""
import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, session, send_file

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "vulnerable.db")
UPLOAD_DIR = os.path.join(BASE, "uploads")
FILES_DIR = os.path.join(BASE, "files")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)
with open(os.path.join(FILES_DIR, "readme.txt"), "w") as fh:
    fh.write("Public readme file.\n")

app = Flask(__name__)
app.secret_key = "supersecret123"  # VULN-01: Hardcoded weak secret key

HOME = """
<h2>Vulnerable Demo App</h2>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/search?q=test">Search</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping tool</a></li>
  <li><a href="/calc?expr=2%2B2">Calculator</a></li>
  <li><a href="/file?name=readme.txt">Download file</a></li>
  <li><a href="/profile/1">Profile (id=1)</a></li>
  <li><a href="/upload">Upload</a></li>
</ul>
"""


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
        "password TEXT, role TEXT, email TEXT)"
    )
    seed = [
        ("admin", "admin123", "admin", "admin@example.com"),
        ("alice", "alice123", "user", "alice@example.com"),
        ("bob", "bob123", "user", "bob@example.com"),
    ]
    for u, p, r, e in seed:
        # VULN-02: Weak hashing (MD5, no salt)
        h = hashlib.md5(p.encode()).hexdigest()
        c.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
            (u, h, r, e),
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
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        h = hashlib.md5(p.encode()).hexdigest()
        # VULN-03: SQL Injection (string formatting in query)
        query = f"SELECT id, username, role FROM users WHERE username='{u}' AND password='{h}'"
        row = get_db().execute(query).fetchone()
        if row:
            session["uid"], session["user"], session["role"] = row
            msg = f"Welcome {row[1]} (role: {row[2]})"
        else:
            msg = "Invalid credentials"  # VULN-04: no rate limiting / lockout
    return render_template_string(
        """<h2>Login</h2><form method="post">
        <input name="username" placeholder="username">
        <input name="password" type="password" placeholder="password">
        <button>Login</button></form><p>""" + msg + "</p>"
    )  # VULN-05: msg template mein concatenate (XSS/SSTI)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN-06: Reflected XSS (user input bina escape ke HTML mein)
    return render_template_string(f"<h2>Search results for: {q}</h2>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN-07: OS Command Injection (shell=True + user input)
    try:
        out = subprocess.check_output(
            "ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT, timeout=10
        )
    except Exception as exc:
        out = str(exc).encode()
    return "<pre>" + out.decode(errors="ignore") + "</pre>"


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # VULN-08: Code Injection via eval()
    try:
        return "Result: " + str(eval(expr))
    except Exception as exc:
        return "Error: " + str(exc)


@app.route("/file")
def download():
    name = request.args.get("name", "readme.txt")
    # VULN-09: Path Traversal (name par koi check nahi)
    return send_file(os.path.join(FILES_DIR, name))


@app.route("/profile/<int:uid>")
def profile(uid):
    # VULN-10: IDOR / Missing authentication & authorization
    row = get_db().execute(
        "SELECT id, username, email, role, password FROM users WHERE id=?", (uid,)
    ).fetchone()
    # VULN-11: Sensitive data exposure (password hash response mein)
    return {"profile": row} if row else ("Not found", 404)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files["file"]
        # VULN-12: Insecure file upload (koi extension/size/name check nahi)
        f.save(os.path.join(UPLOAD_DIR, f.filename))
        return f"Uploaded {f.filename}"
    return """<h2>Upload</h2><form method="post" enctype="multipart/form-data">
    <input type="file" name="file"><button>Upload</button></form>"""


if __name__ == "__main__":
    init_db()
    # VULN-13: Debug mode ON (Werkzeug debugger = remote code execution risk)
    app.run(host="127.0.0.1", port=5000, debug=True)
