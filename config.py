import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

# Telegram Bot Config
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

# Admin Authorization
# Comma-separated Telegram User IDs allowed to access the bot. If empty, any user who talks to the bot is accepted.
_raw_admin_ids = os.getenv("ALLOWED_ADMIN_IDS", "").strip()
ALLOWED_ADMIN_IDS = [int(x.strip()) for x in _raw_admin_ids.split(",") if x.strip().isdigit()]

# Default alert destination chat ID (can be updated dynamically when admin executes /start)
ALERT_CHAT_ID = os.getenv("ALERT_CHAT_ID", "").strip()
if ALERT_CHAT_ID.isdigit() or (ALERT_CHAT_ID.startswith("-") and ALERT_CHAT_ID[1:].isdigit()):
    ALERT_CHAT_ID = int(ALERT_CHAT_ID)
else:
    ALERT_CHAT_ID = None

# Vercel & Supabase Audit Configuration (Primary for Serverless Vercel site)
import re

def _clean_supabase_url(raw: str) -> str:
    default_url = "https://xsppndniabvdntvsivwm.supabase.co"
    if not raw:
        return default_url
    cleaned = raw.strip().strip("'\"")
    # If the user pasted a PostgreSQL connection string, host with db., or bracketed host:
    # e.g., postgresql://postgres:[password]@db.xsppndniabvdntvsivwm.supabase.co:5432/postgres
    # or db.xsppndniabvdntvsivwm.supabase.co
    m = re.search(r'(?:db\.)?([a-z0-9_-]+)\.supabase\.co', cleaned, re.IGNORECASE)
    if m:
        ref = m.group(1)
        if ref.lower() != "db":
            return f"https://{ref}.supabase.co"
    
    cleaned = re.sub(r'[\[\]]', '', cleaned)
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        cleaned = f"https://{cleaned}"
    return cleaned.rstrip('/')

def _clean_audit_logs_url(raw: str) -> str:
    if not raw:
        return ""
    cleaned = raw.strip().strip("'\"")
    # If a database connection string was pasted into AUDIT_LOGS_URL, ignore it
    if cleaned.startswith("postgres://") or cleaned.startswith("postgresql://"):
        return ""
    cleaned = re.sub(r'[\[\]]', '', cleaned)
    return cleaned

VERCEL_APP_URL = os.getenv("VERCEL_APP_URL", "https://pulse-chat-phi-three.vercel.app").strip()
SUPABASE_URL = _clean_supabase_url(os.getenv("SUPABASE_URL", "https://xsppndniabvdntvsivwm.supabase.co"))
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhzcHBuZG5pYWJ2ZG50dnNpdndtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIyOTgxODIsImV4cCI6MjEwNzg3NDE4Mn0.f3jQmV-feyZorkfD1ZWM3dsNBwV3oSjuKsNeGHm2ni4").strip()
SUPABASE_TABLE = os.getenv("SUPABASE_TABLE", "chat_audit_logs").strip()

# Legacy / Custom REST Audit Endpoint (Optional fallback)
AUDIT_LOGS_URL = _clean_audit_logs_url(os.getenv("AUDIT_LOGS_URL", ""))

# Monitoring interval in seconds
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))

# Threat Intelligence (Optional)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

import tempfile

# Directory for generated forensic artifacts (use /tmp on Vercel Serverless)
if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    REPORTS_DIR = Path(tempfile.gettempdir()) / "reports"
    STATE_FILE = Path(tempfile.gettempdir()) / "seen_events.json"
else:
    REPORTS_DIR = Path(__file__).resolve().parent / "reports"
    STATE_FILE = Path(__file__).resolve().parent / "seen_events.json"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
