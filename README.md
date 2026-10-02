# 🛡️ Pulse Chat Forensic Sentinel — Telegram Audit Bot

A cyber-forensic monitoring and audit Telegram bot built for **Pulse Chat** (hosted on Render). The bot continuously inspects live visitor audit logs, detects attacks (SQLi, XSS, Path Traversal, Command Injection, Scrapers, Floods), sends real-time Telegram alerts, and compiles print-ready forensic dossiers (PDF & interactive chat briefings) on any visitor or IP address.

---

## 🌟 Key Capabilities

1. **Autonomous Log Ingestion & Real-Time Monitoring**:
   - Continuously monitors your Render audit log endpoint:
     `https://pulse-chat-x187.onrender.com/api/admin/audit-logs?key=a582bada4cc1da841b5a851cba3e1809`
   - Keeps track of processed event IDs to prevent duplicate alerts.
   - Background polling cycle checks every 15 seconds (configurable).

2. **OWASP Attack & Anomaly Detection Engine**:
   - **SQL Injection (SQLi)**: Identifies `UNION SELECT`, `' OR 1=1`, `INFORMATION_SCHEMA`, sleep delays, etc.
   - **Cross-Site Scripting (XSS)**: Flags `<script>`, event handlers (`onerror=`, `onload=`), cookie theft attempts.
   - **Command Injection (RCE)**: Catches piped shell commands (`; cat`, `| bash`, `powershell`, `$(whoami)`).
   - **Path Traversal / LFI**: Detects directory traversal (`../`, `/etc/passwd`, `.env`, `win.ini`).
   - **Tool & Scraper Fingerprinting**: Discovers automated bots (`sqlmap`, `nikto`, `curl`, `python-requests`, `headlesschrome`).
   - **Application Security Flags**: Automatically escalates events flagged by your Render application (`isFlagged: true`).

3. **Forensic Person Dossier & Attribution**:
   - **Network Attribution**: Geolocation (City, Region, Country), ISP name, Autonomous System (ASN), Coordinates, and Abuse score.
   - **Client Hardware Fingerprint**: Parses raw User-Agent to extract OS (e.g. Windows 10, Android, Linux), Browser (Chrome, Firefox, Safari), device category, and bot probability.
   - **Identity Correlation**: Correlates all handles/usernames used by the same IP address, socket IDs, and targeted chat rooms.
   - **Evidence Audit Trail**: Chronological log of all messages and actions taken by the subject.

4. **Print-Ready Forensic PDF Generator**:
   - Compiles a publication-quality PDF incident dossier (`ReportLab`) with incident case ID, severity badge, network attribution table, device fingerprint, rule violations, and evidence table.
   - Automatically sends the PDF directly to your Telegram chat.

---

## 🚀 Quick Setup Guide

### Step 1: Create Your Bot with BotFather
1. Open Telegram and search for [@BotFather](https://t.me/BotFather).
2. Send `/newbot` to BotFather.
3. Choose a friendly name (e.g. `Pulse Audit Sentinel`).
4. Choose a username ending with `bot` (e.g. `pulse_audit_sentinel_bot`).
5. BotFather will provide an **HTTP API Token** formatted like:
   `7123456789:ABCdefGHIjklMNOpqrstuVWXyz`

### Step 2: Configure Environment Variables
Open the `.env` file in this directory and paste your token:
```ini
TELEGRAM_BOT_TOKEN=7123456789:ABCdefGHIjklMNOpqrstuVWXyz

# (Optional) Restrict access to your Telegram numeric user ID
ALLOWED_ADMIN_IDS=

# Pre-configured audit log endpoint
AUDIT_LOGS_URL=https://pulse-chat-x187.onrender.com/api/admin/audit-logs?key=a582bada4cc1da841b5a851cba3e1809

# Polling frequency in seconds (default: 15)
POLL_INTERVAL_SECONDS=15

# (Optional) Free API key from https://www.abuseipdb.com/ for abuse confidence scoring
ABUSEIPDB_API_KEY=
```

*(To find your Telegram user ID, talk to `@userinfobot` on Telegram).*

---

## 🏃 Running the Bot

### Option A: Start the Telegram Bot
Double-click `run.bat` or run in terminal:
```bash
python bot.py
```

### Option B: Test Without Telegram (Dry-Run Audit)
You can run an immediate audit against your live Render endpoint directly from the command line:
```bash
python test_audit.py
```
This fetches all events, summarizes unique IPs and users, and generates a sample forensic PDF report in `reports/`.

### Option C: Run Attack Simulation Test
Test how the bot detects malicious attacks (SQLi, XSS, RCE, sqlmap) and generates a CRITICAL incident dossier:
```bash
python simulate_attack.py
```

---

## 📱 Telegram Bot Commands Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `/start` | Registers your chat as the alert destination and shows the main dashboard. | `/start` |
| `/status` | View real-time monitoring state, event counts, and last check timestamp. | `/status` |
| `/logs [n]` | View the `n` most recent audit logs from your website. | `/logs 10` |
| `/users` | List all unique visitor usernames with action count & IPs. | `/users` |
| `/ips` | List all tracked IP addresses with activity count. | `/ips` |
| `/audit <IP or User>` | Generate an instant on-demand summary briefing in chat. | `/audit 117.252.20.10` or `/audit alice` |
| `/report <IP or User>` | Generate full forensic dossier **and upload official PDF report**. | `/report 117.252.20.10` or `/report alice` |
| `/scan` | Run an on-demand security scan across all stored events for threats. | `/scan` |
| `/monitor on\|off` | Toggle background real-time alerts. | `/monitor on` |

---

## 📂 Project Architecture

```
agitated-meitner/
├── config.py             # Configuration loader (.env, API URLs, polling intervals)
├── models.py             # Data models for Events, Threats, Intel, and Dossiers
├── log_collector.py      # Async/sync HTTP client for Render audit logs API
├── detector.py           # OWASP Attack & Threat detection engine
├── ip_intel.py           # IP Geolocation, ASN, ISP, and AbuseIPDB reconnaissance
├── fingerprint.py        # Client User-Agent hardware/OS/browser parser
├── forensics.py          # Behavioral forensic dossier aggregation engine
├── pdf_generator.py      # High-resolution PDF report builder (ReportLab)
├── bot.py                # Telegram bot application with background polling loop
├── test_audit.py         # Standalone test runner against live Render logs
├── simulate_attack.py    # Simulated attack runner & tester
├── requirements.txt      # Python dependencies
├── .env                  # Active credentials configuration
├── run.bat               # Windows quick-launcher
└── reports/              # Folder where compiled PDF dossiers are stored
```
