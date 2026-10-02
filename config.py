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

# Website Audit Log API Config
AUDIT_LOGS_URL = os.getenv(
    "AUDIT_LOGS_URL",
    "https://pulse-chat-x187.onrender.com/api/admin/audit-logs?key=a582bada4cc1da841b5a851cba3e1809"
).strip()

# Monitoring interval in seconds
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))

# Threat Intelligence (Optional)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

# Directory for generated forensic artifacts
REPORTS_DIR = Path(__file__).resolve().parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# State cache for seen events
STATE_FILE = Path(__file__).resolve().parent / "seen_events.json"
