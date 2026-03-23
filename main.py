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

import os

port = int(os.environ.get("PORT", 5000))

@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def db_path() -> str:
    os.makedirs(app.instance_path, exist_ok=True)
    return os.path.join(app.instance_path, "thinkobo.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = get_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS courses (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              description TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS lessons (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              course_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              body TEXT NOT NULL,
              position INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS enrollments (
              user_id INTEGER NOT NULL,
              course_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY (user_id, course_id),
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
              FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS lesson_progress (
              user_id INTEGER NOT NULL,
              lesson_id INTEGER NOT NULL,
              completed_at TEXT NOT NULL,
              PRIMARY KEY (user_id, lesson_id),
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
              FOREIGN KEY(lesson_id) REFERENCES lessons(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS website_reviews (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              site_key TEXT NOT NULL,
              reviewer_name TEXT NOT NULL,
              rating INTEGER NOT NULL,
              title TEXT NOT NULL,
              body TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS account_reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              reported_user_id INTEGER,
              reported_email TEXT NOT NULL,
              reporter_email TEXT,
              reason TEXT NOT NULL,
              created_at TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'open',
              FOREIGN KEY(reported_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users);").fetchall()}
        if "totp_secret" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT;")
        if "totp_enabled" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;")
        if "totp_last_used_step" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN totp_last_used_step INTEGER;")

        cur = conn.execute("SELECT COUNT(*) AS c FROM courses;")
        if int(cur.fetchone()["c"]) == 0:
            now = utc_now_iso()
            courses = [
                ("Learning how to learn", "Study smarter with proven techniques.", now),
                ("Math fundamentals", "Build strong foundations step by step.", now),
                ("Intro to programming", "Start coding with practical exercises.", now),
            ]
            conn.executemany(
                "INSERT INTO courses (title, description, created_at) VALUES (?, ?, ?);",
                courses,
            )
            course_rows = conn.execute("SELECT id, title FROM courses;").fetchall()
            title_to_id = {r["title"]: r["id"] for r in course_rows}

            lessons = [
                (
                    title_to_id["Learning how to learn"],
                    "Spaced repetition",
                    "Review over time to remember more.",
                    1,
                    now,
                ),
                (
                    title_to_id["Learning how to learn"],
                    "Active recall",
                    "Test yourself instead of re-reading.",
                    2,
                    now,
                ),
                (title_to_id["Math fundamentals"], "Number sense", "Understand numbers and relationships.", 1, now),
                (title_to_id["Intro to programming"], "Variables", "Store and reuse values in code.", 1, now),
            ]
            conn.executemany(
                "INSERT INTO lessons (course_id, title, body, position, created_at) VALUES (?, ?, ?, ?, ?);",
                lessons,
            )

        sample_reviews = {
            ("Mina S.", 5, "Clean, kid-friendly design", "Super easy for my child to use. The lessons are short and feel achievable."),
            ("Jared P.", 4, "Great start", "The course flow is smooth. Would love more quizzes per topic."),
            ("Anya K.", 5, "Motivating progress", "My kid likes seeing progress and coming back daily. Simple and effective."),
        }
        rows = conn.execute(
            """
            SELECT id, reviewer_name, rating, title, body
            FROM website_reviews
            WHERE site_key = ?;
            """,
            ("thinkobo",),
        ).fetchall()
        if rows and len(rows) == 3:
            existing = {(r["reviewer_name"], int(r["rating"]), r["title"], r["body"]) for r in rows}
            if existing == sample_reviews:
                ids = [int(r["id"]) for r in rows]
                conn.executemany("DELETE FROM website_reviews WHERE id = ?;", [(i,) for i in ids])
        conn.commit()
    finally:
        conn.close()


def current_user():
    if hasattr(g, "_current_user"):
        return g._current_user

    user_id = session.get("user_id")
    if not user_id:
        g._current_user = None
        return None

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, name, email, totp_enabled, created_at FROM users WHERE id = ?;",
            (user_id,),
        ).fetchone()
        g._current_user = dict(row) if row else None
        return g._current_user
    finally:
        conn.close()


def is_admin() -> bool:
    return bool(session.get("is_admin"))


def require_admin():
    if not is_admin():
        return redirect("/admin/login")
    return None


def ensure_admin_csrf_token() -> str:
    token = session.get("admin_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["admin_csrf"] = token
    return token


def verify_admin_csrf(token: str | None) -> bool:
    expected = session.get("admin_csrf")
    return bool(expected) and bool(token) and secrets.compare_digest(expected, token)


def set_autobot(message: str, kind: str = "info") -> None:
    session["autobot"] = {"message": message, "kind": kind, "at": utc_now_iso()}


def pop_autobot():
    return session.pop("autobot", None)


@app.context_processor
def inject_autobot():
    return {"autobot": pop_autobot()}


def pending_2fa_user_id() -> int | None:
    raw = session.get("pending_2fa_user_id")
    try:
        return int(raw) if raw else None
    except (TypeError, ValueError):
        return None


def pending_2fa_user():
    user_id = pending_2fa_user_id()
    if not user_id:
        return None
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, name, email, totp_secret, totp_enabled, totp_last_used_step FROM users WHERE id = ?;",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def base32_secret() -> str:
    # 160-bit secret for TOTP (no padding for nicer display)
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def _b32decode_nopad(secret_b32: str) -> bytes:
    safe = (secret_b32 or "").strip().upper().replace(" ", "")
    pad_len = (-len(safe)) % 8
    safe_padded = safe + ("=" * pad_len)
    return base64.b32decode(safe_padded, casefold=True)


def totp_counter(now: datetime | None = None, step_seconds: int = 30) -> int:
    if now is None:
        now = datetime.now(timezone.utc)
    return int(now.timestamp()) // step_seconds


def totp_code(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = _b32decode_nopad(secret_b32)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code_int = truncated % (10**digits)
    return str(code_int).zfill(digits)


def verify_totp(secret_b32: str, code: str, last_used_step: int | None) -> tuple[bool, int | None]:
    raw = (code or "").strip().replace(" ", "")
    if len(raw) != 6 or not raw.isdigit():
        return False, None

    current = totp_counter()
    for step in (current - 1, current, current + 1):
        expected = totp_code(secret_b32, step)
        if secrets.compare_digest(raw, expected):
            if last_used_step is not None and step <= int(last_used_step):
                return False, None
            return True, step
    return False, None


def twofa_recent_seconds() -> int:
    try:
        return int(os.environ.get("TWOFA_GRACE_SECONDS", "600"))
    except ValueError:
        return 600


def parse_iso_dt(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def is_twofa_recent() -> bool:
    dt = parse_iso_dt(session.get("twofa_recent_at"))
    if not dt:
        return False
    return datetime.now(timezone.utc) - dt <= timedelta(seconds=twofa_recent_seconds())


def mark_twofa_recent() -> None:
    session["twofa_recent_at"] = utc_now_iso()


def twofa_required_response(next_path: str, setup: bool = False, message: str | None = None):
    next_url = "/2fa"
    if setup:
        next_url += "?setup=1"
    else:
        next_url += "?verify=1"
    next_url += "&next=" + quote(next_path or "/dashboard", safe="")
    return (
        jsonify(
            {
                "ok": False,
                "code": "2fa_required",
                "message": message or ("Enable 2FA first." if setup else "2FA required."),
                "next": next_url,
            }
        ),
        403,
    )


def require_serious_2fa(next_path: str):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "message": "Please log in."}), 401
    if not int(user.get("totp_enabled") or 0):
        return twofa_required_response(next_path, setup=True, message="Enable 2FA to do this action.")
    if not is_twofa_recent():
        return twofa_required_response(next_path, setup=False, message="Confirm 2FA to continue.")
    return None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.before_request
def enforce_pending_2fa():
    path = request.path or "/"

    if path.startswith("/static/"):
        return None
    if path.startswith("/admin"):
        return None
    if path.startswith("/2fa"):
        return None
    if path in {"/", "/home", "/auth", "/reviews", "/report-account"}:
        return None
    if path in {
        "/api/login",
        "/api/signup",
        "/api/logout",
        "/api/me",
        "/api/reviews",
        "/api/report-account",
    }:
        if path == "/api/reviews" and request.method != "GET":
            pass
        else:
            return None
    if path.startswith("/api/2fa/"):
        return None

    if pending_2fa_user_id():
        set_autobot("Autobot: Complete 2FA to continue.", "error")
        if path.startswith("/api/"):
            return jsonify({"ok": False, "message": "2FA required."}), 403
        return redirect("/2fa")

    return None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/home")
def marketing_home():
    return render_template("home.html")


@app.route("/auth")
def auth():
    return render_template("auth.html")


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect("/auth")

    conn = get_db()
    try:
        courses = conn.execute(
            """
            SELECT
              c.id,
              c.title,
              c.description,
              EXISTS(
                SELECT 1 FROM enrollments e
                WHERE e.user_id = ? AND e.course_id = c.id
              ) AS enrolled
            FROM courses c
            ORDER BY c.id ASC;
            """,
            (user["id"],),
        ).fetchall()
        return render_template("dashboard.html", user=user, courses=courses)
    finally:
        conn.close()


@app.route("/course/<int:course_id>")
def course(course_id: int):
    user = current_user()
    if not user:
        return redirect("/auth")

    conn = get_db()
    try:
        course_row = conn.execute(
            "SELECT id, title, description FROM courses WHERE id = ?;",
            (course_id,),
        ).fetchone()
        if not course_row:
            return redirect("/dashboard")

        enrolled_row = conn.execute(
            "SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?;",
            (user["id"], course_id),
        ).fetchone()
        enrolled = bool(enrolled_row)

        lessons = conn.execute(
            """
            SELECT id, course_id, title, body, position
            FROM lessons
            WHERE course_id = ?
            ORDER BY position ASC, id ASC;
            """,
            (course_id,),
        ).fetchall()

        return render_template(
            "course.html",
            user=user,
            course=course_row,
            enrolled=enrolled,
            lessons=lessons,
        )
    finally:
        conn.close()


@app.get("/api/me")
def me():
    return jsonify({"ok": True, "user": current_user()})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = normalize_email(data.get("email") or "")
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"ok": False, "message": "Please fill all fields."}), 400

    if "@" not in email or "." not in email:
        return jsonify({"ok": False, "message": "Please provide a valid email."}), 400

    if len(password) < 8:
        return jsonify({"ok": False, "message": "Password must be at least 8 characters."}), 400

    password_hash = generate_password_hash(password)
    conn = get_db()
    try:
        try:
            cur = conn.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?);",
                (name, email, password_hash, utc_now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "message": "Account already exists."}), 409

        session.clear()
        session["user_id"] = cur.lastrowid
        session.pop("twofa_recent_at", None)
        return jsonify(
            {
                "ok": True,
                "message": "Account created successfully.",
                "name": name,
                "email": email,
                "next": "/dashboard",
            }
        )
    finally:
        conn.close()


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get("email") or "")
    password = data.get("password") or ""

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, name, email, totp_enabled, password_hash FROM users WHERE email = ?;",
            (email,),
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            return jsonify({"ok": False, "message": "Invalid email or password."}), 401

        session.clear()
        session["user_id"] = int(row["id"])
        session.pop("twofa_recent_at", None)
        return jsonify(
            {
                "ok": True,
                "message": "Login successful.",
                "name": row["name"],
                "email": row["email"],
                "next": "/dashboard",
            }
        )
    finally:
        conn.close()


@app.post("/api/enroll")
def enroll():
    gate = require_serious_2fa("/dashboard")
    if gate is not None:
        return gate

    user = current_user()
    if not user:
        return jsonify({"ok": False, "message": "Please log in."}), 401

    data = request.get_json(silent=True) or {}
    course_id = data.get("course_id")
    try:
        course_id_int = int(course_id)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "Invalid course."}), 400

    conn = get_db()
    try:
        course = conn.execute("SELECT id FROM courses WHERE id = ?;", (course_id_int,)).fetchone()
        if not course:
            return jsonify({"ok": False, "message": "Course not found."}), 404

        conn.execute(
            "INSERT OR IGNORE INTO enrollments (user_id, course_id, created_at) VALUES (?, ?, ?);",
            (user["id"], course_id_int, utc_now_iso()),
        )
        conn.commit()
        return jsonify({"ok": True, "course_id": course_id_int})
    finally:
        conn.close()


init_db()

@app.route("/quiz")
def quiz():
    user = current_user()
    if not user:
        return redirect("/auth")
    return render_template("quiz.html")

def normalize_site_key(raw: str | None) -> str:
    safe = (raw or "").strip().lower()
    if not safe:
        return "thinkobo"
    if safe in {"thinkobo", "thinkobo.com", "www.thinkobo.com"}:
        return "thinkobo"
    return safe


def get_site_meta(site_key: str) -> dict:
    sites = {
        "thinkobo": {
            "key": "thinkobo",
            "name": "Thinkobo",
            "tagline": "Where young minds start thinking",
            "logo": "favicon.svg",
            "official": True,
        },
    }
    return sites.get(site_key) or {
        "key": site_key,
        "name": site_key.title() if site_key else "Website",
        "tagline": "Reviews and ratings",
        "logo": "favicon.svg",
        "official": False,
    }


@app.get("/api/reviews")
def api_reviews_list():
    site_key = normalize_site_key(request.args.get("site"))
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT id, reviewer_name, rating, title, body, created_at
            FROM website_reviews
            WHERE site_key = ?
            ORDER BY created_at DESC, id DESC;
            """,
            (site_key,),
        ).fetchall()
        reviews = [
            {
                "id": int(r["id"]),
                "name": r["reviewer_name"],
                "rating": int(r["rating"]),
                "title": r["title"],
                "body": r["body"],
                "date": (r["created_at"] or "")[:10],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
        return jsonify({"ok": True, "site": get_site_meta(site_key), "reviews": reviews})
    finally:
        conn.close()


@app.post("/api/reviews")
def api_reviews_create():
    data = request.get_json(silent=True) or {}
    gate = require_serious_2fa(f"/reviews?site={normalize_site_key(data.get('site'))}")
    if gate is not None:
        return gate

    site_key = normalize_site_key(data.get("site"))
    reviewer_name = (data.get("name") or "").strip() or "Anonymous"
    title = (data.get("title") or "").strip()
    body = (data.get("body") or "").strip()

    try:
        rating = int(data.get("rating"))
    except (TypeError, ValueError):
        rating = 0

    if not (1 <= rating <= 5):
        return jsonify({"ok": False, "message": "Rating must be between 1 and 5."}), 400
    if len(reviewer_name) > 40:
        return jsonify({"ok": False, "message": "Name is too long."}), 400
    if not title or len(title) > 80:
        return jsonify({"ok": False, "message": "Title is required (max 80 chars)."}), 400
    if not body or len(body) > 800:
        return jsonify({"ok": False, "message": "Review text is required (max 800 chars)."}), 400

    conn = get_db()
    try:
        created_at = utc_now_iso()
        cur = conn.execute(
            """
            INSERT INTO website_reviews (site_key, reviewer_name, rating, title, body, created_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (site_key, reviewer_name, rating, title, body, created_at),
        )
        conn.commit()
        return jsonify(
            {
                "ok": True,
                "review": {
                    "id": int(cur.lastrowid),
                    "site_key": site_key,
                    "name": reviewer_name,
                    "rating": rating,
                    "title": title,
                    "body": body,
                    "date": created_at[:10],
                    "created_at": created_at,
                },
            }
        )
    finally:
        conn.close()


@app.get("/report-account")
def report_account_page():
    return render_template("report_account.html")


@app.post("/api/report-account")
def api_report_account():
    gate = require_serious_2fa("/report-account")
    if gate is not None:
        return gate

    data = request.get_json(silent=True) or {}
    reported_email = normalize_email(data.get("reported_email") or "")
    reporter_email = (data.get("reporter_email") or "").strip()
    reason = (data.get("reason") or "").strip()

    if not reported_email or "@" not in reported_email or "." not in reported_email:
        return jsonify({"ok": False, "message": "Please provide a valid account email."}), 400
    if reporter_email:
        reporter_email = normalize_email(reporter_email)
        if "@" not in reporter_email or "." not in reporter_email:
            return jsonify({"ok": False, "message": "Your email is invalid."}), 400
    if not reason or len(reason) > 800:
        return jsonify({"ok": False, "message": "Reason is required (max 800 chars)."}), 400

    conn = get_db()
    try:
        user_row = conn.execute(
            "SELECT id FROM users WHERE email = ?;",
            (reported_email,),
        ).fetchone()
        reported_user_id = int(user_row["id"]) if user_row else None
        conn.execute(
            """
            INSERT INTO account_reports (reported_user_id, reported_email, reporter_email, reason, created_at, status)
            VALUES (?, ?, ?, ?, ?, 'open');
            """,
            (reported_user_id, reported_email, reporter_email or None, reason, utc_now_iso()),
        )
        conn.commit()
        return jsonify({"ok": True})
    finally:
        conn.close()

@app.get("/2fa")
def twofa_page():
    pending = pending_2fa_user()
    user = current_user()
    target = pending or user
    if not target:
        return redirect("/auth")

    force_setup = (request.args.get("setup") or "").strip() == "1"
    force_verify = (request.args.get("verify") or "").strip() == "1"
    next_path = (request.args.get("next") or "/dashboard").strip() or "/dashboard"

    if force_setup:
        mode = "setup"
    elif force_verify:
        mode = "verify"
    else:
        mode = "verify" if int(target.get("totp_enabled") or 0) else "setup"

    return render_template("2fa.html", user=target, pending=bool(pending), mode=mode, next_path=next_path)


def _twofa_actor():
    user = current_user()
    if user:
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id, name, email, totp_secret, totp_enabled, totp_last_used_step FROM users WHERE id = ?;",
                (user["id"],),
            ).fetchone()
            return (dict(row) if row else None), False
        finally:
            conn.close()
    return None, False


@app.post("/api/2fa/setup")
def api_2fa_setup():
    actor, _is_pending = _twofa_actor()
    if not actor:
        return jsonify({"ok": False, "message": "Please log in."}), 401
    if int(actor.get("totp_enabled") or 0):
        return jsonify({"ok": False, "message": "2FA is already enabled."}), 400

    secret_b32 = base32_secret()
    issuer = "Thinkobo"
    label = f"{issuer}:{actor['email']}"
    otpauth = (
        "otpauth://totp/"
        + quote(label)
        + "?secret="
        + secret_b32
        + "&issuer="
        + quote(issuer)
        + "&algorithm=SHA1&digits=6&period=30"
    )

    conn = get_db()
    try:
        conn.execute(
            """
            UPDATE users
            SET totp_secret = ?, totp_enabled = 0, totp_last_used_step = NULL
            WHERE id = ?;
            """,
            (secret_b32, int(actor["id"])),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"ok": True, "secret": secret_b32, "otpauth_uri": otpauth})


@app.post("/api/2fa/enable")
def api_2fa_enable():
    actor, _is_pending = _twofa_actor()
    if not actor:
        return jsonify({"ok": False, "message": "Please log in."}), 401
    if int(actor.get("totp_enabled") or 0):
        return jsonify({"ok": False, "message": "2FA is already enabled."}), 400
    if not actor.get("totp_secret"):
        return jsonify({"ok": False, "message": "Please set up 2FA first."}), 400

    data = request.get_json(silent=True) or {}
    code = data.get("code") or ""
    next_path = (data.get("next") or "/dashboard").strip() or "/dashboard"
    ok, used_step = verify_totp(actor["totp_secret"], code, actor.get("totp_last_used_step"))
    if not ok or used_step is None:
        return jsonify({"ok": False, "message": "Invalid code."}), 400

    conn = get_db()
    try:
        conn.execute(
            """
            UPDATE users
            SET totp_enabled = 1, totp_last_used_step = ?
            WHERE id = ?;
            """,
            (int(used_step), int(actor["id"])),
        )
        conn.commit()
    finally:
        conn.close()

    mark_twofa_recent()
    set_autobot("Autobot: 2FA enabled.", "ok")
    return jsonify({"ok": True, "next": next_path})


@app.post("/api/2fa/verify")
def api_2fa_verify():
    actor = pending_2fa_user()
    pending = True
    if not actor:
        actor, _ = _twofa_actor()
        pending = False
    if not actor:
        return jsonify({"ok": False, "message": "Please log in."}), 401
    if not int(actor.get("totp_enabled") or 0):
        return jsonify({"ok": False, "message": "2FA is not enabled. Set it up first."}), 400
    if not actor.get("totp_secret"):
        return jsonify({"ok": False, "message": "2FA secret missing. Set it up again."}), 400

    data = request.get_json(silent=True) or {}
    code = data.get("code") or ""
    next_path = (data.get("next") or "/dashboard").strip() or "/dashboard"
    ok, used_step = verify_totp(actor["totp_secret"], code, actor.get("totp_last_used_step"))
    if not ok or used_step is None:
        return jsonify({"ok": False, "message": "Invalid code."}), 400

    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET totp_last_used_step = ? WHERE id = ?;",
            (int(used_step), int(actor["id"])),
        )
        conn.commit()
    finally:
        conn.close()

    if pending:
        session["user_id"] = int(actor["id"])
        session.pop("pending_2fa_user_id", None)
    mark_twofa_recent()
    set_autobot("Autobot: 2FA verified.", "ok")
    return jsonify({"ok": True, "next": next_path})


@app.get("/admin/login")
def admin_login_page():
    if is_admin():
        return redirect("/admin")
    return render_template("admin_login.html", error=None)


@app.post("/admin/login")
def admin_login_submit():
    if is_admin():
        return redirect("/admin")
    password = (request.form.get("password") or "").strip()
    expected = os.environ.get("ADMIN_PASSWORD", "SecureDinoThinkoboFX#&*$FSThinkMeSolo")
    if not password or not secrets.compare_digest(password, expected):
        set_autobot("Autobot: Incorrect admin password.", "error")
        return render_template("admin_login.html", error="Invalid password."), 401
    session["is_admin"] = True
    ensure_admin_csrf_token()
    set_autobot("Autobot: Admin access granted.", "ok")
    return redirect("/admin")


@app.post("/admin/logout")
def admin_logout():
    if not is_admin():
        return redirect("/admin/login")
    if not verify_admin_csrf(request.form.get("csrf")):
        return "Bad CSRF token", 400
    session.pop("is_admin", None)
    session.pop("admin_csrf", None)
    set_autobot("Autobot: Logged out.", "info")
    return redirect("/admin/login")


@app.get("/admin")
def admin_panel():
    gate = require_admin()
    if gate is not None:
        return gate

    csrf = ensure_admin_csrf_token()
    conn = get_db()
    try:
        reports = conn.execute(
            """
            SELECT id, reported_user_id, reported_email, reporter_email, reason, created_at, status
            FROM account_reports
            WHERE status = 'open'
            ORDER BY created_at DESC, id DESC;
            """
        ).fetchall()
        reviews = conn.execute(
            """
            SELECT id, site_key, reviewer_name, rating, title, body, created_at
            FROM website_reviews
            ORDER BY created_at DESC, id DESC
            LIMIT 100;
            """
        ).fetchall()
        return render_template("admin.html", csrf=csrf, reports=reports, reviews=reviews)
    finally:
        conn.close()


@app.post("/admin/reports/<int:report_id>/resolve")
def admin_resolve_report(report_id: int):
    gate = require_admin()
    if gate is not None:
        return gate
    if not verify_admin_csrf(request.form.get("csrf")):
        return "Bad CSRF token", 400
    conn = get_db()
    try:
        conn.execute("UPDATE account_reports SET status = 'resolved' WHERE id = ?;", (report_id,))
        conn.commit()
    finally:
        conn.close()
    set_autobot("Autobot: Report resolved.", "ok")
    return redirect("/admin")


@app.post("/admin/reviews/<int:review_id>/delete")
def admin_delete_review(review_id: int):
    gate = require_admin()
    if gate is not None:
        return gate
    if not verify_admin_csrf(request.form.get("csrf")):
        return "Bad CSRF token", 400
    conn = get_db()
    try:
        conn.execute("DELETE FROM website_reviews WHERE id = ?;", (review_id,))
        conn.commit()
    finally:
        conn.close()
    set_autobot("Autobot: Review deleted.", "ok")
    return redirect("/admin")


@app.get("/reviews")
def reviews_page():
    site_key = normalize_site_key(request.args.get("site"))
    site = get_site_meta(site_key)

    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT reviewer_name, rating, title, body, created_at
            FROM website_reviews
            WHERE site_key = ?
            ORDER BY created_at DESC, id DESC;
            """,
            (site_key,),
        ).fetchall()
        reviews = [
            {
                "name": r["reviewer_name"],
                "rating": int(r["rating"]),
                "title": r["title"],
                "body": r["body"],
                "date": (r["created_at"] or "")[:10],
            }
            for r in rows
        ]
    finally:
        conn.close()

    return render_template("reviews.html", site=site, reviews=reviews)


@app.route("/Thinkobo Reviews")
def legacy_thinkobo_reviews():
    return redirect("/reviews?site=thinkobo")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port, debug=True)
