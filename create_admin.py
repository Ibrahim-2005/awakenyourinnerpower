from app import create_app
from models import db, User
from werkzeug.security import generate_password_hash
import os

app = create_app()

with app.app_context():
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")

    user = User(
        username=username,
        password_hash=generate_password_hash(password)
    )

    db.session.add(user)
    db.session.commit()

    print("Admin user created")