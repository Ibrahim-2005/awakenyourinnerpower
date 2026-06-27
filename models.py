from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin,db.Model):
    __tablename__ = "users"

    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )


class Booking(db.Model):
    __tablename__ = "bookings"

    id = db.Column(db.BigInteger, primary_key=True)

    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(255))

    package = db.Column(db.Text, nullable=False)

    session_date = db.Column(db.Date, nullable=False)
    slot = db.Column(db.Text, nullable=False)

    note = db.Column(db.Text)
    booking_reference = db.Column(db.String(20), unique=True, nullable=True)
    public_token = db.Column(
        db.String(255),
        unique=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending"
    )

    payment_status = db.Column(
        db.String(20),
        nullable=False,
        default="unpaid"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


class BlockedSlot(db.Model):
    __tablename__ = "blocked_slots"

    id = db.Column(db.BigInteger, primary_key=True)

    session_date = db.Column(
        db.String(20),
        nullable=False
    )

    slot = db.Column(
        db.String(100),
        nullable=False
    )

    note = db.Column(db.Text)


class RateLimit(db.Model):
    __tablename__ = "rate_limits"

    key = db.Column(
        db.String(255),
        primary_key=True
    )

    window_start = db.Column(
        db.Integer,
        nullable=False
    )

    count = db.Column(
        db.Integer,
        nullable=False
    )