import hmac
import os
import json
import binascii
import hashlib
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, session, abort, flash
)

app = Flask(__name__)
# Use a secret key — in production set via environment var
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

DIST_FOLDER = os.path.join(os.getcwd(), "dist")
ADMIN_C_FILE = os.path.join(os.getcwd(), "admin_c.txt")  # file that stores admin creds
FEEDBACK_FILE = os.path.join(os.getcwd(), "feedback.txt")
VERSION_FILE = os.path.join(os.getcwd(), "version.txt")

# PBKDF2 settings
HASH_NAME = "sha256"
ITERATIONS = 200_000
SALT_BYTES = 16

def read_version():
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, "r") as f:
            return f.read().strip()
    return "0.0.0"

def append_feedback(text):
    if text and text.strip():
        with open(FEEDBACK_FILE, "a", encoding="utf-8") as f:
            f.write(text.strip() + "\n")

def admin_exists():
    return os.path.exists(ADMIN_C_FILE)

def create_admin(username: str, password: str):
    if admin_exists():
        raise RuntimeError("Admin already exists")

    salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, ITERATIONS)
    payload = {
        "username": username,
        "salt": binascii.hexlify(salt).decode("ascii"),
        "iterations": ITERATIONS,
        "hash": binascii.hexlify(dk).decode("ascii"),
        "algo": HASH_NAME
    }
    tmp = ADMIN_C_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, ADMIN_C_FILE)

def verify_admin(username: str, password: str) -> bool:
    if not admin_exists():
        return False
    with open(ADMIN_C_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if username != data.get("username"):
        return False
    salt = binascii.unhexlify(data["salt"].encode("ascii"))
    iterations = int(data.get("iterations", ITERATIONS))
    algo = data.get("algo", HASH_NAME)
    expected = binascii.unhexlify(data["hash"].encode("ascii"))
    dk = hashlib.pbkdf2_hmac(algo, password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)

# ---- Routes ----

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    if request.method == "POST":
        fb = request.form.get("feedback", "")
        append_feedback(fb)
        message = "Thank you for your feedback!"
    version = read_version()
    return render_template("index.html", version=version, message=message, admin_exists=admin_exists())

@app.route("/downloads/<path:filename>")
def downloads(filename):
    filepath = os.path.join(DIST_FOLDER, filename)
    if os.path.exists(filepath):
        return send_from_directory(DIST_FOLDER, filename, as_attachment=True)
    return "File not found", 404

@app.route("/build-guide")
def build_guide():
    return render_template("build_guide.html", version=read_version())


@app.route("/admin/signup", methods=["GET", "POST"])
def admin_signup():
    if admin_exists():
        abort(404)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("signup.html")
        if password != password2:
            flash("Passwords do not match", "error")
            return render_template("signup.html")
        create_admin(username, password)
        flash("Signup complete — please log in", "success")
        return redirect(url_for("admin_login"))
    return render_template("signup.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_admin(username, password):
            session["admin_logged_in"] = True
            session["admin_user"] = username
            flash("Logged in", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid credentials", "error")
            return render_template("login.html")
    return render_template("login.html", admin_exists=admin_exists())

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_user", None)
    flash("Logged out", "success")
    return redirect(url_for("index"))

def require_admin(view_func):
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper


@app.route("/admin/dashboard", methods=["GET", "POST"])
@require_admin
def admin_dashboard():
    feedback_preview = []
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            feedback_preview = list(reversed([line.strip() for line in f if line.strip()]))[:200]

    # Load current version
    version = read_version()

    return render_template(
        "admin_dashboard.html",
        feedback_preview=feedback_preview,
        version=version
    )


# --- Edit version number ---
@app.route("/admin/edit_version", methods=["POST"])
@require_admin
def edit_version():
    new_version = request.form.get("version", "").strip()
    if new_version:
        with open(VERSION_FILE, "w", encoding="utf-8") as f:
            f.write(new_version)
        flash("Version updated successfully!", "success")
    else:
        flash("Invalid version value.", "error")
    return redirect(url_for("admin_dashboard"))


# --- Edit software code ---
@app.route("/admin/edit_code", methods=["GET", "POST"])
@require_admin
def edit_code():
    filepath = os.path.join(DIST_FOLDER, "blocker_linux")  # adjust filename if needed

    # only allow editing if file is text-like
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        flash("This file is not editable (not UTF-8 text).", "error")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        new_content = request.form.get("content", "")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)
        flash("Code updated successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("edit_code.html", content=content)



@app.route("/admin/delete_account", methods=["POST"])
@require_admin
def admin_delete_account():
    if admin_exists():
        os.remove(ADMIN_C_FILE)
        session.pop("admin_logged_in", None)
        session.pop("admin_user", None)
        flash("Admin account deleted. Signup is available again.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
