import os
import sqlite3
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
source = Path(os.getenv("DATABASE_PATH", ROOT / "instance" / "awaken.db"))
if not source.is_absolute():
    source = ROOT / source
backup_dir = ROOT / "backups"
backup_dir.mkdir(parents=True, exist_ok=True)
target = backup_dir / f"awaken-{datetime.now():%Y%m%d-%H%M%S}.db"

with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
    src.backup(dst)

print(target)
