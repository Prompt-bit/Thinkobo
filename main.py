from __future__ import annotations

import os
import sqlite3
import secrets
import hashlib
import base64
import hmac
import struct
from urllib.parse import quote
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, redirect, render_template, request, session, g
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

port = int(os.environ.get("PORT", 5000))

# -------------------- UTIL --------------------

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def normalize_email(email: str):
    return email.strip().lower()

def db_path():
    os.makedirs(app.instance_path, exist_ok=True)
    return os.path.join(app.instance_path, "thinkobo.db")

def get_db():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn

# -------------------- DB INIT --------------------

def init_db():
    conn = get_db()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT,
          email TEXT UNIQUE,
          password_hash TEXT,
          created_at TEXT
        );
        """)
        conn.commit()
    finally:
        conn.close()

# -------------------- USER --------------------

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, name, email FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

# -------------------- ROUTES --------------------

@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/auth")
def auth():
    return render_template("auth.html")

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect("/auth")
    return render_template("dashboard.html", user=user)

# -------------------- AUTH API --------------------

@app.post("/api/signup")
def signup():
    data = request.get_json() or {}
    name = data.get("name")
    email = normalize_email(data.get("email", ""))
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"ok": False, "message": "Missing fields"}), 400

    conn = get_db()
    try:
        try:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), utc_now_iso())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "message": "User exists"}), 409

        return jsonify({"ok": True})
    finally:
        conn.close()

@app.post("/api/login")
def login():
    data = request.get_json() or {}
    email = normalize_email(data.get("email", ""))
    password = data.get("password", "")

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if not row or not check_password_hash(row["password_hash"], password):
            return jsonify({"ok": False}), 401

        session["user_id"] = row["id"]
        return jsonify({"ok": True})
    finally:
        conn.close()

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/me")
def me():
    return jsonify({"user": current_user()})

# -------------------- START --------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=port, debug=True)
