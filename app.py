import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
import logging
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    session, url_for,send_file
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user,
    logout_user
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
SLOTS = [
    "11:00 AM – 12:00 PM",
    "12:00 PM – 1:00 PM",
    "1:00 PM – 2:00 PM",
    "3:00 PM – 4:00 PM",
    "4:00 PM – 5:00 PM",
    "5:00 PM – 6:00 PM",
]
PACKAGES = ["Single Session (60 min)", "10-Session Transformation Program"]
STATUSES = ["pending", "confirmed", "completed", "cancelled"]


def create_app(test_config=None):
    app = Flask(__name__)
    app_env = os.getenv("APP_ENV", "development").lower()
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-change-this-secret"),
        DATABASE=os.getenv("DATABASE_PATH", str(BASE_DIR / "awaken.db")),
        APP_ENV=app_env,
        IS_PRODUCTION=app_env == "production",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=app_env == "production",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=64 * 1024,
        PREFERRED_URL_SCHEME="https" if app_env == "production" else "http",
        PENDING_HOLD_MINUTES=int(os.getenv("PENDING_HOLD_MINUTES", "30")),
        TRUST_PROXY=os.getenv("TRUST_PROXY", "0") == "1",
        LOG_DIR=os.getenv("LOG_DIR", str(BASE_DIR / "logs")),
        PHONE_NUMBER=os.getenv("PHONE_NUMBER", "+91 00000 00000"),
        WHATSAPP_NUMBER=os.getenv("WHATSAPP_NUMBER", "910000000000"),
        CONTACT_EMAIL=os.getenv("CONTACT_EMAIL", "hello@example.com"),
        UPI_ID=os.getenv("UPI_ID", "yourname@upi"),
        PAYMENT_NAME=os.getenv("PAYMENT_NAME", "Your Name"),
        BANK_NAME=os.getenv("BANK_NAME", ""),
        BANK_ACCOUNT=os.getenv("BANK_ACCOUNT", ""),
        BANK_IFSC=os.getenv("BANK_IFSC", ""),
        CALLMEBOT_PHONE=os.getenv("CALLMEBOT_PHONE", ""),
        CALLMEBOT_APIKEY=os.getenv("CALLMEBOT_APIKEY", ""),
    )
    if test_config:
        app.config.update(test_config)

    validate_production_config(app)
    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    configure_logging(app)

    login_manager = LoginManager()
    login_manager.login_view = "admin_login"
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    class User(UserMixin):
        def __init__(self, row):
            self.id = str(row["id"])
            self.username = row["username"]
            self.password_hash = row["password_hash"]

    @login_manager.user_loader
    def load_user(user_id):
        row = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return User(row) if row else None

    def csrf_protect(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not submitted or not secrets.compare_digest(submitted, session.get("_csrf_token", "")):
                abort(400, "Invalid CSRF token")
            return view(*args, **kwargs)
        return wrapped

    def rate_limit(name, limit, window_seconds, methods=None):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if methods and request.method not in methods:
                    return view(*args, **kwargs)
                identity = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
                identity = identity.split(",")[0].strip()
                key = f"{name}:{identity}"
                now = int(time.time())
                window = now - (now % window_seconds)
                db = get_db()
                row = db.execute(
                    "SELECT window_start, count FROM rate_limits WHERE key = ?", (key,)
                ).fetchone()
                if row and row["window_start"] == window and row["count"] >= limit:
                    retry_after = window_seconds - (now - window)
                    response = jsonify({"error": "Too many requests. Please try again shortly."})
                    response.status_code = 429
                    response.headers["Retry-After"] = str(retry_after)
                    return response
                if row and row["window_start"] == window:
                    db.execute("UPDATE rate_limits SET count = count + 1 WHERE key = ?", (key,))
                else:
                    db.execute(
                        """INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
                           ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = 1""",
                        (key, window),
                    )
                db.commit()
                return view(*args, **kwargs)
            return wrapped
        return decorator

    @app.context_processor
    def inject_globals():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return {
            "csrf_token": token,
            "phone_number": app.config["PHONE_NUMBER"],
            "whatsapp_number": app.config["WHATSAPP_NUMBER"],
            "contact_email": app.config["CONTACT_EMAIL"],
            "current_year": datetime.now().year,
        }

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.before_request
    def maintain_booking_holds():
        if request.endpoint in {"static", "healthz"}:
            return None
        expire_pending_bookings(app)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if app.config["IS_PRODUCTION"] and request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if request.path.startswith("/admin") or request.path.startswith("/payment/"):
            response.headers["Cache-Control"] = "no-store, private"
        return response

    @app.get("/")
    def index():
        min_date = (date.today() + timedelta(days=1)).isoformat()
        return render_template(
            "index.html", slots=SLOTS, packages=PACKAGES, min_date=min_date
        )

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html")

    @app.get("/healthz")
    def healthz():
        try:
            get_db().execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return jsonify({"status": "unhealthy"}), 503
        return jsonify({"status": "ok"})

    @app.get("/api/availability")
    @rate_limit("availability", 60, 60)
    def availability():
        selected_date = request.args.get("date", "")
        try:
            date.fromisoformat(selected_date)
        except ValueError:
            return jsonify({"error": "Choose a valid date."}), 400
        taken = {
            row["slot"]
            for row in get_db().execute(
                """SELECT slot FROM bookings
                   WHERE session_date = ? AND status IN ('pending', 'confirmed')
                   UNION
                   SELECT slot FROM blocked_slots WHERE session_date = ?""",
                (selected_date, selected_date),
            ).fetchall()
        }
        return jsonify({"available": [slot for slot in SLOTS if slot not in taken]})

    @app.post("/book")
    @rate_limit("booking", 8, 3600)
    @csrf_protect
    def book():
        form = {key: request.form.get(key, "").strip() for key in
                ("name", "phone", "email", "package", "session_date", "slot", "note")}
        errors = []
        if request.form.get("website", "").strip():
            abort(400)
        if len(form["name"]) < 2 or len(form["name"]) > 100:
            errors.append("Please enter your name.")
        if not re.fullmatch(r"[0-9+()\-\s]{7,24}", form["phone"]):
            errors.append("Please enter a valid phone number.")
        if form["email"] and (
            len(form["email"]) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", form["email"])
        ):
            errors.append("Please enter a valid email address.")
        if len(form["note"]) > 1500:
            errors.append("Please shorten your note.")
        if request.form.get("privacy_consent") != "yes":
            errors.append("Please accept the privacy and booking policy.")
        if form["package"] not in PACKAGES:
            errors.append("Please choose a valid package.")
        if form["slot"] not in SLOTS:
            errors.append("Please choose a valid time slot.")
        try:
            chosen_date = date.fromisoformat(form["session_date"])
            if chosen_date <= date.today():
                errors.append("Please choose a future date.")
        except ValueError:
            errors.append("Please choose a valid date.")
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for("index", _anchor="book"))

        db = get_db()
        unavailable = db.execute(
            """SELECT 1 FROM bookings
               WHERE session_date = ? AND slot = ?
               AND status IN ('pending', 'confirmed')
               UNION SELECT 1 FROM blocked_slots
               WHERE session_date = ? AND slot = ?""",
            (form["session_date"], form["slot"], form["session_date"], form["slot"]),
        ).fetchone()
        if unavailable:
            flash("That time was just reserved. Please choose another slot.", "error")
            return redirect(url_for("index", _anchor="book"))

        booking_token = secrets.token_urlsafe(24)
        try:
            cursor = db.execute(
                """INSERT INTO bookings
                   (name, phone, email, package, session_date, slot, note, public_token)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (*form.values(), booking_token),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That slot is no longer available.", "error")
            return redirect(url_for("index", _anchor="book"))

        booking_id = cursor.lastrowid
        send_admin_notification(app, booking_id, form)
        return redirect(url_for("payment", booking_token=booking_token))

    @app.get("/payment/<booking_token>")
    @rate_limit("payment", 60, 60)
    def payment(booking_token):
        booking = get_db().execute(
            "SELECT * FROM bookings WHERE public_token = ?", (booking_token,)
        ).fetchone()
        if not booking:
            abort(404)
        return render_template("payment.html", booking=booking)

    @app.route("/admin/login", methods=["GET", "POST"])
    @rate_limit("admin-login", 8, 900, methods={"POST"})
    def admin_login():
        if current_user.is_authenticated:
            return redirect(url_for("admin_dashboard"))
        if request.method == "POST":
            submitted = request.form.get("csrf_token", "")
            if not submitted or not secrets.compare_digest(submitted, session.get("_csrf_token", "")):
                abort(400)
            row = get_db().execute(
                "SELECT * FROM users WHERE username = ?",
                (request.form.get("username", "").strip(),),
            ).fetchone()
            if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
                session.clear()
                login_user(User(row))
                session.permanent = True
                session["_csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin_dashboard"))
            time.sleep(0.35)
            flash("Incorrect username or password.", "error")
        return render_template("admin/login.html")

    @app.post("/admin/logout")
    @login_required
    @csrf_protect
    def admin_logout():
        logout_user()
        return redirect(url_for("admin_login"))

    @app.get("/admin")
    @login_required
    def admin_dashboard():
        db = get_db()
        today = date.today()
        week_end = today + timedelta(days=7)
        pending_count = db.execute(
            "SELECT COUNT(*) AS count FROM bookings WHERE status = 'pending'"
        ).fetchone()["count"]
        todays = db.execute(
            "SELECT * FROM bookings WHERE session_date = ? AND status != 'cancelled' ORDER BY slot",
            (today.isoformat(),),
        ).fetchall()
        upcoming = db.execute(
            """SELECT * FROM bookings WHERE session_date BETWEEN ? AND ?
               AND status != 'cancelled' ORDER BY session_date, slot""",
            (today.isoformat(), week_end.isoformat()),
        ).fetchall()
        return render_template(
            "admin/dashboard.html",
            pending_count=pending_count,
            todays=todays,
            upcoming=upcoming,
        )

    @app.get("/admin/calendar")
    @login_required
    def admin_calendar():
        db = get_db()

        pending = db.execute(
            "SELECT COUNT(*) FROM bookings WHERE status='pending'"
        ).fetchone()[0]

        confirmed = db.execute(
            "SELECT COUNT(*) FROM bookings WHERE status='confirmed'"
        ).fetchone()[0]

        completed = db.execute(
            "SELECT COUNT(*) FROM bookings WHERE status='completed'"
        ).fetchone()[0]

        blocked = db.execute(
            "SELECT COUNT(*) FROM blocked_slots"
        ).fetchone()[0]

        return render_template(
            "admin/calendar.html",
            slots=SLOTS,
            pending=pending,
            confirmed=confirmed,
            completed=completed,
            blocked=blocked
        )
    @app.get("/admin/events")
    @login_required
    def admin_events():
        db = get_db()
        bookings = db.execute("SELECT * FROM bookings").fetchall()
        blocks = db.execute("SELECT * FROM blocked_slots").fetchall()
        colors = {
            "pending": "#e8b96a",
            "confirmed": "#6b2d8c",
            "completed": "#3f8a6f",
            "cancelled": "#8a7d88",
        }
        events = [{
            "id": f"booking-{row['id']}",
            "title": f"{row['slot']} · {row['name']}",
            "start": row["session_date"],
            "allDay": True,
            "backgroundColor": colors[row["status"]],
            "borderColor": colors[row["status"]],
            "extendedProps": {
                "kind": "booking", "bookingId": row["id"], "status": row["status"],
                "phone": row["phone"], "package": row["package"], "slot": row["slot"],
            },
        } for row in bookings]
        events += [{
            "id": f"block-{row['id']}",
            "title": f"{row['slot']} · Blocked",
            "start": row["session_date"],
            "allDay": True,
            "backgroundColor": "#c8419a",
            "borderColor": "#c8419a",
            "extendedProps": {"kind": "block", "blockId": row["id"], "slot": row["slot"]},
        } for row in blocks]
        return jsonify(events)

    @app.route("/admin/bookings", methods=["GET"])
    @login_required
    def admin_bookings():
        clauses, values = [], []
        status = request.args.get("status", "")
        query = request.args.get("q", "").strip()
        selected_date = request.args.get("date", "")
        if status in STATUSES:
            clauses.append("status = ?")
            values.append(status)
        if selected_date:
            clauses.append("session_date = ?")
            values.append(selected_date)
        if query:
            clauses.append("(name LIKE ? OR phone LIKE ? OR email LIKE ?)")
            wildcard = f"%{query}%"
            values.extend([wildcard, wildcard, wildcard])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = get_db().execute(
            f"SELECT * FROM bookings {where} ORDER BY session_date DESC, slot", values
        ).fetchall()
        return render_template(
            "admin/bookings.html", bookings=rows, statuses=STATUSES,
            selected_status=status, selected_date=selected_date, query=query
        )

    @app.post("/admin/bookings/<int:booking_id>/status")
    @login_required
    @csrf_protect
    def update_booking_status(booking_id):
        status = request.form.get("status", "")
        payment_status = request.form.get("payment_status", "")
        if status not in STATUSES or payment_status not in ("unpaid", "paid"):
            abort(400)
        db = get_db()
        db.execute(
            """UPDATE bookings SET status = ?, payment_status = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (status, payment_status, booking_id),
        )
        db.commit()
        flash("Booking updated.", "success")
        return redirect(request.referrer or url_for("admin_bookings"))
    
    @app.post("/admin/bookings/<int:booking_id>/delete")
    @login_required
    @csrf_protect
    def delete_booking(booking_id):
        db = get_db()

        db.execute(
            "DELETE FROM bookings WHERE id = ?",
            (booking_id,)
        )

        db.commit()

        flash("Booking deleted successfully.", "success")

        return redirect(url_for("admin_bookings"))

    @app.post("/admin/blocks")
    @login_required
    @csrf_protect
    def add_block():
        session_date = request.form.get("session_date", "")
        slot = request.form.get("slot", "")
        if slot not in SLOTS:
            abort(400)
        try:
            date.fromisoformat(session_date)
        except ValueError:
            abort(400)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO blocked_slots (session_date, slot, note) VALUES (?, ?, ?)",
                (session_date, slot, request.form.get("note", "").strip()),
            )
            db.commit()
            flash("Slot blocked.", "success")
        except sqlite3.IntegrityError:
            flash("That slot is already blocked.", "error")
        return redirect(url_for("admin_calendar"))

    @app.post("/admin/blocks/<int:block_id>/delete")
    @login_required
    @csrf_protect
    def delete_block(block_id):
        db = get_db()
        db.execute("DELETE FROM blocked_slots WHERE id = ?", (block_id,))
        db.commit()
        flash("Slot reopened.", "success")
        return redirect(url_for("admin_calendar"))

    @app.get("/admin/db-backup")
    @login_required
    def db_backup():
        return send_file(
            app.config["DATABASE"],
            as_attachment=True,
            download_name="awaken.db"
        )
    @app.route("/admin/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            submitted = request.form.get("csrf_token", "")
            if not submitted or not secrets.compare_digest(submitted, session.get("_csrf_token", "")):
                abort(400)
            db = get_db()
            row = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not check_password_hash(row["password_hash"], current):
                flash("Current password is incorrect.", "error")
            elif len(new) < 12:
                flash("New password must be at least 12 characters.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            else:
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new), current_user.id),
                )
                db.commit()
                session["_csrf_token"] = secrets.token_urlsafe(32)
                flash("Password changed.", "success")
                return redirect(url_for("admin_dashboard"))
        return render_template("admin/change_password.html")

    with app.app_context():
        init_db(app)
    return app


def get_db():
    if "db" not in g:
        from flask import current_app
        db_path = current_app.config["DATABASE"]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 10000")
    return g.db


def init_db(app):
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            package TEXT NOT NULL,
            session_date DATE NOT NULL,
            slot TEXT NOT NULL,
            note TEXT,
            public_token TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','confirmed','completed','cancelled')),
            payment_status TEXT NOT NULL DEFAULT 'unpaid'
                CHECK(payment_status IN ('unpaid','paid')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX IF NOT EXISTS active_slot_unique
        ON bookings(session_date, slot)
        WHERE status IN ('pending', 'confirmed');
        CREATE TABLE IF NOT EXISTS blocked_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_date TEXT NOT NULL,
            slot TEXT NOT NULL,
            note TEXT,
            UNIQUE(session_date, slot)
        );
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL
        );
        """
    )
    columns = {row["name"] for row in db.execute("PRAGMA table_info(bookings)").fetchall()}
    if "public_token" not in columns:
        db.execute("ALTER TABLE bookings ADD COLUMN public_token TEXT")
    for row in db.execute("SELECT id FROM bookings WHERE public_token IS NULL").fetchall():
        db.execute(
            "UPDATE bookings SET public_token = ? WHERE id = ?",
            (secrets.token_urlsafe(24), row["id"]),
        )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS booking_public_token_unique ON bookings(public_token)"
    )
    username = app.config.get("ADMIN_USERNAME") or os.getenv("ADMIN_USERNAME", "admin")
    existing = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if not existing:
        password = app.config.get("ADMIN_PASSWORD") or os.getenv("ADMIN_PASSWORD", "change-me-now")
        db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
    db.commit()


def expire_pending_bookings(app):
    cutoff = datetime.utcnow() - timedelta(minutes=app.config["PENDING_HOLD_MINUTES"])
    db = get_db()
    db.execute(
        """UPDATE bookings SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
           WHERE status = 'pending' AND payment_status = 'unpaid' AND created_at < ?""",
        (cutoff.strftime("%Y-%m-%d %H:%M:%S"),),
    )
    db.execute(
        "DELETE FROM rate_limits WHERE window_start < ?",
        (int(time.time()) - 86400,),
    )
    db.commit()


def validate_production_config(app):
    if app.config.get("TESTING") or not app.config["IS_PRODUCTION"]:
        return
    secret = app.config["SECRET_KEY"]
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    placeholders = {
        app.config["PHONE_NUMBER"],
        app.config["CONTACT_EMAIL"],
        app.config["UPI_ID"],
    }
    errors = []
    if len(secret) < 32 or secret == "dev-change-this-secret":
        errors.append("SECRET_KEY must be a random value of at least 32 characters")
    if len(admin_password) < 12 or admin_password == "change-me-now":
        errors.append("ADMIN_PASSWORD must contain at least 12 characters")
    if any(value in {"+91 00000 00000", "hello@example.com", "yourname@upi"} for value in placeholders):
        errors.append("replace all contact and payment placeholder values")
    if errors:
        raise RuntimeError("Unsafe production configuration: " + "; ".join(errors))


def configure_logging(app):
    if app.config.get("TESTING"):
        return
    log_dir = Path(app.config["LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / "awaken.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def send_admin_notification(app, booking_id, form):
    phone = app.config["CALLMEBOT_PHONE"]
    api_key = app.config["CALLMEBOT_APIKEY"]
    if not phone or not api_key or app.config.get("TESTING"):
        return
    message = (
    "🌸 NEW BOOKING\n\n"
    f"Client: {form['name']}\n"
    f"Phone: {form['phone']}\n"
    f"Date: {form['session_date']}\n"
    f"Time: {form['slot']}\n"
    f"Package: {form['package']}\n\n"
    "Please check the admin panel."
)
    try:
        query = urlencode({"phone": phone, "text": message, "apikey": api_key})
        with urlopen(f"https://api.callmebot.com/whatsapp.php?{query}", timeout=8):
            pass
    except (URLError, TimeoutError):
        app.logger.exception("CallMeBot notification failed")


app = create_app()


if __name__ == "__main__":
    app.run(debug=not app.config["IS_PRODUCTION"], port=5000)
