import os
import re
import secrets
import time
import resend
from datetime import date, datetime, timedelta
from datetime import time as dt_time
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
from sqlalchemy import or_
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, Booking, BlockedSlot, RateLimit
from zoneinfo import ZoneInfo
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
SLOTS = [
    "11:00 AM – 12:00 PM",
    "12:00 PM – 1:00 PM",
    "1:00 PM – 2:00 PM",
    "3:00 PM – 4:00 PM",
    "4:00 PM – 5:00 PM",
    "5:00 PM – 6:00 PM",
    "7:00 PM – 8:00 PM (999/-)",
]
SLOT_START_TIMES = {
    "11:00 AM – 12:00 PM": dt_time(11, 0),
    "12:00 PM – 1:00 PM": dt_time(12, 0),
    "1:00 PM – 2:00 PM": dt_time(13, 0),
    "3:00 PM – 4:00 PM": dt_time(15, 0),
    "4:00 PM – 5:00 PM": dt_time(16, 0),
    "5:00 PM – 6:00 PM": dt_time(17, 0),
    "7:00 PM – 8:00 PM (999/-)": dt_time(19, 0),
}
PACKAGES = ["Single Session (60 min)", "10-Session Transformation Program"]
STATUSES = ["pending", "confirmed", "completed", "cancelled"]

def create_app(test_config=None):
    app = Flask(__name__)
    app_env = os.getenv("APP_ENV", "development").lower()
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-change-this-secret"),
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
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    app.config.update(
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv("SMTP_EMAIL"),
        MAIL_PASSWORD=os.getenv("SMTP_PASSWORD"),
    )
    if test_config:
        app.config.update(test_config)

    validate_production_config(app)
    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    configure_logging(app)
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "admin_login"
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    class LegacyUser(UserMixin):
        def __init__(self, row):
            self.id = str(row["id"])
            self.username = row["username"]
            self.password_hash = row["password_hash"]

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

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

                identity = request.headers.get(
                    "X-Forwarded-For",
                    request.remote_addr or "unknown"
                )

                identity = identity.split(",")[0].strip()
                key = f"{name}:{identity}"
                now = int(time.time())
                window = now - (now % window_seconds)

                row = RateLimit.query.filter_by(key=key).first()

                if (
                    row
                    and row.window_start == window
                    and row.count >= limit
                ):
                    retry_after = window_seconds - (now - window)

                    response = jsonify({
                        "error": "Too many requests. Please try again shortly."
                    })

                    response.status_code = 429
                    response.headers["Retry-After"] = str(retry_after)
                    return response

                if row and row.window_start == window:

                    row.count += 1

                else:

                    if row:
                        row.window_start = window
                        row.count = 1
                    else:
                        row = RateLimit(
                            key=key,
                            window_start=window,
                            count=1
                        )
                        db.session.add(row)

                db.session.commit()

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
        min_date = date.today().isoformat()
        return render_template(
            "index.html", slots=SLOTS, packages=PACKAGES, min_date=min_date
        )

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html")

    @app.get("/healthz")
    def healthz():
        try:
            db.session.execute(db.text("SELECT 1"))
            return jsonify({"status": "ok"})
        except Exception:
            return jsonify({"status": "unhealthy"}), 503
    @app.get("/api/availability")
    @rate_limit("availability", 60, 60)
    def availability():
        selected_date = request.args.get("date", "")

        try:
            chosen_date = date.fromisoformat(selected_date)
        except ValueError:
            return jsonify({"error": "Choose a valid date."}), 400

        booked_slots = {
            booking.slot
            for booking in Booking.query.filter(
                Booking.session_date == chosen_date,
                Booking.status.in_(["pending", "confirmed"])
            ).all()
        }

        blocked_slots = {
            blocked.slot
            for blocked in BlockedSlot.query.filter_by(
                session_date=selected_date
            ).all()
        }

        taken = booked_slots.union(blocked_slots)

        available_slots = [
            slot for slot in SLOTS
            if slot not in taken
        ]

        if chosen_date == date.today():
            now_time = datetime.now(ZoneInfo("Asia/Kolkata").time)
            print("NOW:",now_time)
            print("AVAILABLE BEFORE:",available_slots)
            available_slots = [
                slot
                for slot in available_slots
                if SLOT_START_TIMES[slot] > now_time
            ]
            print("AVAILABLE AFTER:", available_slots)

        return jsonify({
            "available": available_slots
        })

    @app.post("/book")
    @rate_limit("booking", 100, 3600)
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
        if (len(form["email"]) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", form["email"])):
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
            if chosen_date == date.today():
                now_time = datetime.now(ZoneInfo("Asia/Kolkata")).time()

                if SLOT_START_TIMES[form["slot"]] <= now_time:
                    errors.append("This time slot has already passed.")
            if chosen_date < date.today():
                errors.append("Please choose a future date.")
        except ValueError:
            errors.append("Please choose a valid date.")
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for("index", _anchor="book"))
        
        booking_exists = Booking.query.filter(Booking.session_date == chosen_date,Booking.slot == form["slot"],Booking.status.in_(["pending", "confirmed"])).first()
        blocked_exists = BlockedSlot.query.filter_by(session_date=form["session_date"],slot=form["slot"]).first()
        unavailable = booking_exists or blocked_exists
        
        if unavailable:
            flash("That time was just reserved. Please choose another slot.", "error")
            return redirect(url_for("index", _anchor="book"))

        booking_token = secrets.token_urlsafe(24)
        try:
            booking = Booking(
                name=form["name"],
                phone=form["phone"],
                email=form["email"],
                package=form["package"],
                session_date=chosen_date,
                slot=form["slot"],
                note=form["note"],
                public_token=booking_token,
            )

            db.session.add(booking)
            db.session.commit()

        except Exception as e:
            print("Booking Error:", e)
            db.session.rollback()

            flash("That slot is no longer available.", "error")
            return redirect(url_for("index", _anchor="book"))

        booking_id = booking.id
        # send_admin_notification(app, booking_id, form)
        try:
            send_booking_email(form)
        except Exception as e:
            print("EMAIL ERROR:", repr(e))
        return redirect(url_for("payment", booking_token=booking_token))

    @app.get("/payment/<booking_token>")
    @rate_limit("payment", 60, 60)
    def payment(booking_token):
        booking = Booking.query.filter_by(public_token=booking_token).first()
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
            user = User.query.filter_by(username=request.form.get("username", "").strip()).first()
            if user and check_password_hash(user.password_hash,request.form.get("password", "")):
                session.clear()
                login_user(user)
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
        today = date.today()
        week_end = today + timedelta(days=7)
        pending_count = Booking.query.filter_by(status="pending").count()
        todays = (Booking.query.filter(Booking.session_date == today,Booking.status != "cancelled").order_by(Booking.slot).all())
        upcoming = (
    Booking.query
    .filter(
        Booking.session_date.between(today, week_end),
        Booking.status != "cancelled"
    )
    .order_by(
        Booking.session_date,
        Booking.slot
    )
    .all()
)
        return render_template(
            "admin/dashboard.html",
            pending_count=pending_count,
            todays=todays,
            upcoming=upcoming,
        )

    @app.get("/admin/calendar")
    @login_required
    def admin_calendar():

        pending = Booking.query.filter_by(
            status="pending"
        ).count()

        confirmed = Booking.query.filter_by(
            status="confirmed"
        ).count()

        completed = Booking.query.filter_by(
            status="completed"
        ).count()

        blocked = BlockedSlot.query.count()

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

        bookings = Booking.query.all()
        blocks = BlockedSlot.query.all()

        colors = {
            "pending": "#e8b96a",
            "confirmed": "#6b2d8c",
            "completed": "#3f8a6f",
            "cancelled": "#8a7d88",
        }

        events = [
            {
                "id": f"booking-{row.id}",
                "title": f"{row.slot} · {row.name}",
                "start": str(row.session_date),
                "allDay": True,
                "backgroundColor": colors.get(row.status, "#8a7d88"),
                "borderColor": colors.get(row.status, "#8a7d88"),
                "extendedProps": {
                    "kind": "booking",
                    "bookingId": row.id,
                    "status": row.status,
                    "phone": row.phone,
                    "package": row.package,
                    "slot": row.slot,
                },
            }
            for row in bookings
        ]

        events += [
            {
                "id": f"block-{row.id}",
                "title": f"{row.slot} · Blocked",
                "start": row.session_date,
                "allDay": True,
                "backgroundColor": "#c8419a",
                "borderColor": "#c8419a",
                "extendedProps": {
                    "kind": "block",
                    "blockId": row.id,
                    "slot": row.slot,
                },
            }
            for row in blocks
        ]

        return jsonify(events)
    @app.route("/admin/bookings", methods=["GET"])
    @login_required
    def admin_bookings():

        status = request.args.get("status", "")
        query = request.args.get("q", "").strip()
        selected_date = request.args.get("date", "")

        bookings_query = Booking.query

        if status in STATUSES:
            bookings_query = bookings_query.filter(
                Booking.status == status
            )

        if selected_date:
            bookings_query = bookings_query.filter(
                Booking.session_date == selected_date
            )

        if query:
            wildcard = f"%{query}%"

            bookings_query = bookings_query.filter(
                or_(
                    Booking.name.ilike(wildcard),
                    Booking.phone.ilike(wildcard),
                    Booking.email.ilike(wildcard)
                )
            )

        rows = bookings_query.order_by(
            Booking.session_date.desc(),
            Booking.slot
        ).all()

        return render_template(
            "admin/bookings.html",
            bookings=rows,
            statuses=STATUSES,
            selected_status=status,
            selected_date=selected_date,
            query=query
        )

    @app.post("/admin/bookings/<int:booking_id>/status")
    @login_required
    @csrf_protect
    def update_booking_status(booking_id):
        status = request.form.get("status", "")
        payment_status = request.form.get("payment_status", "")
        if status not in STATUSES or payment_status not in ("unpaid", "paid"):
            abort(400)
        booking = Booking.query.get_or_404(booking_id)
        booking.status = status
        booking.payment_status = payment_status

        db.session.commit()
        flash("Booking updated.", "success")
        return redirect(request.referrer or url_for("admin_bookings"))
    
    @app.post("/admin/bookings/<int:booking_id>/delete")
    @login_required
    @csrf_protect
    def delete_booking(booking_id):

        booking = Booking.query.get_or_404(booking_id)

        db.session.delete(booking)

        db.session.commit()

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
            selected_date = date.fromisoformat(session_date)
        except ValueError:
            abort(400)
        existing_booking = Booking.query.filter(Booking.session_date == selected_date,Booking.slot == slot,Booking.status.in_(["pending", "confirmed"])).first()

        if existing_booking:
            flash(f"This slot is already booked by {existing_booking.name}.","error")
            return redirect(url_for("admin_calendar"))
        existing_block = BlockedSlot.query.filter_by(session_date=session_date,slot=slot).first()

        if existing_block:
            flash("This slot is already blocked.", "error")
            return redirect(url_for("admin_calendar"))
        try:
            block = BlockedSlot(
                session_date=session_date,
                slot=slot,
                note=request.form.get("note", "").strip()
            )

            db.session.add(block)
            db.session.commit()

            flash("Slot blocked.", "success")

        except Exception as e:
            db.session.rollback()
            print("Block Error:", e)
            flash("Unable to block slot.", "error")
        return redirect(url_for("admin_calendar"))

    @app.post("/admin/blocks/<int:block_id>/delete")
    @login_required
    @csrf_protect
    def delete_block(block_id):

        block = BlockedSlot.query.get_or_404(block_id)

        db.session.delete(block)

        db.session.commit()

        flash("Slot reopened.", "success")

        return redirect(url_for("admin_calendar"))


    @app.route("/admin/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            submitted = request.form.get("csrf_token", "")
            if not submitted or not secrets.compare_digest(submitted, session.get("_csrf_token", "")):
                abort(400)
            user = User.query.get(int(current_user.id))
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not check_password_hash(user.password_hash, current):
                flash("Current password is incorrect.", "error")
            elif len(new) < 12:
                flash("New password must be at least 12 characters.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            else:
                user.password_hash = generate_password_hash(new)
                db.session.commit()
                session["_csrf_token"] = secrets.token_urlsafe(32)
                flash("Password changed.", "success")
                return redirect(url_for("admin_dashboard"))
        return render_template("admin/change_password.html")

    with app.app_context():
        db.create_all()
    return app


def expire_pending_bookings(app):

    cutoff = datetime.utcnow() - timedelta(
        minutes=app.config["PENDING_HOLD_MINUTES"]
    )

    Booking.query.filter(
        Booking.status == "pending",
        Booking.payment_status == "unpaid",
        Booking.created_at < cutoff
    ).update(
        {
            "status": "cancelled",
            "updated_at": datetime.utcnow()
        },
        synchronize_session=False
    )

    RateLimit.query.filter(
        RateLimit.window_start < (int(time.time()) - 86400)
    ).delete(
        synchronize_session=False
    )

    db.session.commit()


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
    
resend.api_key = os.getenv("RESEND_API_KEY")


def send_booking_email(form):
    resend.Emails.send({
        "from": "onboarding@resend.dev",
        "to": [os.getenv("CONTACT_EMAIL")],
        "subject": "New Booking Received",
        "html": f"""
        <h2>New Booking Received</h2>

        <p><strong>Name:</strong> {form['name']}</p>
        <p><strong>Email:</strong> {form['email']}</p>
        <p><strong>Phone:</strong> {form['phone']}</p>
        <p><strong>Package:</strong> {form['package']}</p>
        <p><strong>Date:</strong> {datetime.strptime(form['session_date'], "%Y-%m-%d").strftime("%d/%m/%Y")}</p>
        <p><strong>Slot:</strong> {form['slot']}</p>

        <p><strong>Notes:</strong></p>
        <p>{form['note']}</p>
        """
    })

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
