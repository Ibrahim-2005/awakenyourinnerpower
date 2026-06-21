import os
import tempfile
import unittest
from datetime import date, timedelta

from app import create_app


class AppTestCase(unittest.TestCase):
    def setUp(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        self.db_path = path
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test",
            "DATABASE": path,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        os.unlink(self.db_path)

    def csrf(self):
        self.client.get("/")
        with self.client.session_transaction() as session:
            return session["_csrf_token"]

    def test_home_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Awaken Your", response.data)

    def test_booking_and_duplicate_slot_prevention(self):
        future = (date.today() + timedelta(days=3)).isoformat()
        payload = {
            "csrf_token": self.csrf(),
            "name": "Test Client",
            "phone": "9999999999",
            "email": "",
            "package": "Single Session (60 min)",
            "session_date": future,
            "slot": "11:00 AM – 12:00 PM",
            "note": "",
            "privacy_consent": "yes",
        }
        first = self.client.post("/book", data=payload)
        self.assertEqual(first.status_code, 302)
        payment = self.client.get(first.location)
        self.assertEqual(payment.status_code, 200)
        self.assertIn(b"Request received", payment.data)
        self.assertNotEqual(first.location, "/payment/1")
        second = self.client.post("/book", data=payload, follow_redirects=True)
        self.assertIn(b"just reserved", second.data)

    def test_admin_login(self):
        response = self.client.post("/admin/login", data={
            "csrf_token": self.csrf(),
            "username": "admin",
            "password": "change-me-now",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin", response.location)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.assertEqual(self.client.get("/admin/calendar").status_code, 200)
        self.assertEqual(self.client.get("/admin/bookings").status_code, 200)
        self.assertEqual(self.client.get("/admin/events").status_code, 200)

    def test_security_headers_and_health(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(self.client.get("/healthz").json, {"status": "ok"})

    def test_booking_requires_consent(self):
        future = (date.today() + timedelta(days=4)).isoformat()
        response = self.client.post("/book", data={
            "csrf_token": self.csrf(),
            "name": "Test Client",
            "phone": "9999999999",
            "email": "",
            "package": "Single Session (60 min)",
            "session_date": future,
            "slot": "12:00 PM â€“ 1:00 PM",
            "note": "",
        }, follow_redirects=True)
        self.assertIn(b"accept the privacy", response.data)

    def test_payment_ids_are_not_public(self):
        self.assertEqual(self.client.get("/payment/1").status_code, 404)


if __name__ == "__main__":
    unittest.main()
