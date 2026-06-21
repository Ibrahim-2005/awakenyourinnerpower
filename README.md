# Awaken Your Inner Power

Production-oriented Flask booking website with SQLite, token-protected payment instructions, WhatsApp notifications, admin authentication, calendar management, rate limiting, secure headers, and automatic expiry of abandoned booking holds.

## Local development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m flask --app app run --host=0.0.0.0
```

Use `APP_ENV=development` locally. Open `http://127.0.0.1:5000`.

## Production configuration

Copy `.env.example` to `.env` and replace every placeholder. Production startup intentionally fails when the secret, admin password, phone, email, or UPI values remain unsafe.

Required values:

- `APP_ENV=production`
- `SECRET_KEY`: at least 32 random characters
- `ADMIN_PASSWORD`: at least 12 characters
- Real phone, WhatsApp, email, UPI and payment-name values
- `DATABASE_PATH` on persistent storage
- `TRUST_PROXY=1` when HTTPS is terminated by a trusted hosting proxy

Generate a secret:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Production server

Do not use `flask run` publicly. On Windows:

```powershell
.\.venv\Scripts\waitress-serve.exe --listen=0.0.0.0:8000 --call app:create_app
```

The included `render.yaml` can deploy the app to Render with a persistent disk. Set all missing private environment variables in the Render dashboard.

## Operational checks

- Health endpoint: `/healthz`
- Logs: `logs/awaken.log`
- Pending unpaid slots expire after `PENDING_HOLD_MINUTES`
- Admin and booking endpoints are rate-limited
- Payment pages use random, non-sequential access tokens

Back up SQLite:

```powershell
.\.venv\Scripts\python.exe scripts\backup_db.py
```

Schedule this command daily and copy backups off the server.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Before launch, test a real booking, WhatsApp notification, payment screenshot, admin confirmation, cancellation, and expired pending hold.
