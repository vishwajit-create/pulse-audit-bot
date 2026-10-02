import os
import sys
import asyncio
import logging
from datetime import datetime
from typing import Optional

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

import config
from log_collector import LogCollector
from detector import ThreatDetector
from forensics import ForensicInvestigator
from pdf_generator import generate_forensic_pdf

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Pulse Chat Forensic Sentinel is Running OK\n")
    def log_message(self, format, *args):
        pass  # Suppress noisy healthcheck logs

def start_health_server():
    port = int(os.getenv("PORT", "0"))
    if port > 0:
        try:
            server = HTTPServer(("0.0.0.0", port), HealthHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            logger.info(f"Health-check HTTP server active on port {port} (Render / Cloud ready)")
        except Exception as e:
            logger.warning(f"Could not bind health-check server on port {port}: {e}")

# Setup Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("audit_bot")

collector = LogCollector()
monitoring_active = True
active_alert_chat: Optional[int] = config.ALERT_CHAT_ID

def is_authorized(user_id: int) -> bool:
    """Check if the requesting Telegram user is authorized."""
    if not config.ALLOWED_ADMIN_IDS:
        return True  # If no admin IDs restricted, allow
    return user_id in config.ALLOWED_ADMIN_IDS

def get_dashboard_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton("📊 Status", callback_data="btn_status"),
            InlineKeyboardButton("🔍 Scan Now", callback_data="btn_scan"),
        ],
        [
            InlineKeyboardButton("👥 Visitors", callback_data="btn_users"),
            InlineKeyboardButton("🌐 IP Catalog", callback_data="btn_ips"),
        ],
        [
            InlineKeyboardButton("📜 Recent Logs", callback_data="btn_logs"),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

# ----------------- COMMAND HANDLERS ----------------- #

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global active_alert_chat
    user = update.effective_user
    chat_id = update.effective_chat.id

    if not is_authorized(user.id):
        await update.message.reply_text("⛔ Access Denied: You are not authorized to use this audit bot.")
        return

    # Automatically set alert chat to this user
    active_alert_chat = chat_id

    welcome_text = (
        f"🛡️ <b>Pulse Chat Forensic Sentinel</b>\n\n"
        f"Welcome, <b>{user.first_name}</b>!\n"
        f"This bot is actively monitoring your Render website audit logs:\n"
        f"<code>{config.AUDIT_LOGS_URL.split('?')[0]}</code>\n\n"
        f"<b>Available Commands:</b>\n"
        f"• <code>/status</code> - View monitoring & sync statistics\n"
        f"• <code>/logs [count]</code> - Inspect recent website audit logs\n"
        f"• <code>/users</code> - List all observed visitor usernames\n"
        f"• <code>/ips</code> - List all tracked IP addresses with geolocation\n"
        f"• <code>/audit &lt;IP or Username&gt;</code> - Instant threat briefing\n"
        f"• <code>/report &lt;IP or Username&gt;</code> - Generate & send full PDF Dossier\n"
        f"• <code>/scan</code> - Run an immediate manual security audit\n"
        f"• <code>/monitor [on|off]</code> - Toggle background real-time alerts\n\n"
        f"<i>Alert notifications are now routed to this chat.</i>"
    )

    await update.message.reply_text(
        welcome_text,
        parse_mode=ParseMode.HTML,
        reply_markup=get_dashboard_keyboard()
    )

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    try:
        stats = collector.get_summary_stats()
        status_mode = "🟢 Active (Polling every 15s)" if monitoring_active else "🔴 Paused"
        text = (
            f"📊 <b>System Telemetry & Status</b>\n\n"
            f"• <b>Monitoring State:</b> {status_mode}\n"
            f"• <b>Total Events Indexed:</b> {stats['total_events']}\n"
            f"• <b>Unique IPs Tracked:</b> {stats['unique_ips']}\n"
            f"• <b>Unique Visitor Handles:</b> {stats['unique_senders']}\n"
            f"• <b>Flagged Anomalies:</b> {stats['flagged_events']}\n"
            f"• <b>Alert Destination:</b> <code>{active_alert_chat}</code>\n"
            f"• <b>Last Checked:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, parse_mode=ParseMode.HTML, reply_markup=get_dashboard_keyboard()
            )
        else:
            await update.message.reply_text(
                text, parse_mode=ParseMode.HTML, reply_markup=get_dashboard_keyboard()
            )
    except Exception as e:
        msg = f"⚠️ Failed to query telemetry: {e}"
        if update.callback_query:
            await update.callback_query.message.reply_text(msg)
        else:
            await update.message.reply_text(msg)

async def cmd_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    count = 5
    if context.args and context.args[0].isdigit():
        count = min(15, max(1, int(context.args[0])))

    try:
        events = collector.fetch_events()
        recent = events[-count:]
        if not recent:
            await (update.message or update.callback_query.message).reply_text("No logs recorded yet.")
            return

        lines = [f"📜 <b>Recent Audit Events (Last {len(recent)}):</b>\n"]
        for ev in recent:
            flag_badge = "🚩 " if (ev.is_flagged or ev.flags) else ""
            lines.append(
                f"• <b>[{ev.timestamp[11:19]}]</b> {flag_badge}<b>{ev.sender}</b> ({ev.event_type})\n"
                f"   IP: <code>{ev.ip}</code> | Target: <i>{ev.target}</i>\n"
                f"   Payload: <code>{ev.message[:80]}</code>\n"
            )

        text = "\n".join(lines)
        if update.callback_query:
            await update.callback_query.message.reply_text(text, parse_mode=ParseMode.HTML)
        else:
            await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    except Exception as e:
        await (update.message or update.callback_query.message).reply_text(f"⚠️ Error fetching logs: {e}")

async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    try:
        events = collector.fetch_events()
        # Aggregate by sender
        user_map = {}
        for ev in events:
            sender = ev.sender or "anonymous"
            if sender not in user_map:
                user_map[sender] = {"count": 0, "ips": set(), "flagged": 0}
            user_map[sender]["count"] += 1
            if ev.ip:
                user_map[sender]["ips"].add(ev.ip)
            if ev.is_flagged or ev.flags:
                user_map[sender]["flagged"] += 1

        lines = ["👥 <b>Observed Visitor Handles:</b>\n"]
        for sender, data in sorted(user_map.items(), key=lambda x: x[1]["count"], reverse=True):
            flag_str = f" | 🚩 Flags: {data['flagged']}" if data['flagged'] else ""
            ip_str = ", ".join(list(data["ips"])[:2])
            lines.append(
                f"• <b>{sender}</b> ({data['count']} events{flag_str})\n"
                f"   IPs: <code>{ip_str}</code>\n"
                f"   Audit: /report_{sender.replace(' ', '_')}\n"
            )

        text = "\n".join(lines[:20])
        if update.callback_query:
            await update.callback_query.message.reply_text(text, parse_mode=ParseMode.HTML)
        else:
            await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    except Exception as e:
        await (update.message or update.callback_query.message).reply_text(f"⚠️ Error aggregating users: {e}")

async def cmd_ips(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    try:
        events = collector.fetch_events()
        ip_map = {}
        for ev in events:
            ip = ev.ip or "0.0.0.0"
            if ip not in ip_map:
                ip_map[ip] = {"count": 0, "senders": set(), "flagged": 0}
            ip_map[ip]["count"] += 1
            if ev.sender:
                ip_map[ip]["senders"].add(ev.sender)
            if ev.is_flagged or ev.flags:
                ip_map[ip]["flagged"] += 1

        lines = ["🌐 <b>Observed IP Addresses:</b>\n"]
        for ip, data in sorted(ip_map.items(), key=lambda x: x[1]["count"], reverse=True):
            clean_ip_cmd = ip.replace('.', '_')
            senders_str = ", ".join(list(data["senders"])[:3])
            lines.append(
                f"• <code>{ip}</code> ({data['count']} events)\n"
                f"   Aliases: <i>{senders_str}</i>\n"
                f"   Audit: /report_{clean_ip_cmd}\n"
            )

        text = "\n".join(lines[:20])
        if update.callback_query:
            await update.callback_query.message.reply_text(text, parse_mode=ParseMode.HTML)
        else:
            await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    except Exception as e:
        await (update.message or update.callback_query.message).reply_text(f"⚠️ Error aggregating IPs: {e}")

async def handle_report_generation(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    subject_query: str,
    generate_pdf: bool = True
):
    """Core routine to compile a forensic investigation and deliver report."""
    target_msg = update.message or (update.callback_query.message if update.callback_query else None)
    if not target_msg:
        return

    status_msg = await target_msg.reply_text(
        f"🔍 <i>Conducting cyber forensic analysis for <b>{subject_query}</b>...</i>",
        parse_mode=ParseMode.HTML
    )

    try:
        events = collector.fetch_events()
        # Check if subject is IP or User
        is_ip = ("." in subject_query and any(c.isdigit() for c in subject_query))
        
        if is_ip:
            matched = [e for e in events if e.ip.strip() == subject_query.strip()]
            subject_type = "IP"
        else:
            matched = [e for e in events if e.sender.strip().lower() == subject_query.strip().lower()]
            subject_type = "USER"

        if not matched:
            await status_msg.edit_text(
                f"❌ <b>No records found</b> for subject <code>{subject_query}</code> in website audit logs.",
                parse_mode=ParseMode.HTML
            )
            return

        # Build Forensic Dossier
        dossier = ForensicInvestigator.build_dossier_from_events(matched, subject_type, subject_query)

        # Build Summary Briefing
        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "CLEAN": "✅"
        }.get(dossier.threat.severity, "ℹ️")

        geo_str = "N/A"
        if dossier.ip_intel:
            geo_str = f"{dossier.ip_intel.city}, {dossier.ip_intel.country} ({dossier.ip_intel.isp})"

        device_str = "N/A"
        if dossier.fingerprint:
            device_str = f"{dossier.fingerprint.browser_family} on {dossier.fingerprint.os_family} ({dossier.fingerprint.device_family})"

        briefing = (
            f"🛡️ <b>FORENSIC INVESTIGATION REPORT</b>\n"
            f"<b>Case Ref:</b> <code>{dossier.case_id}</code>\n"
            f"<b>Target {dossier.subject_type}:</b> <code>{dossier.subject_value}</code>\n"
            f"<b>Threat Status:</b> {severity_emoji} <b>{dossier.threat.severity}</b> ({dossier.threat.risk_score}/100)\n\n"
            f"📍 <b>Location & ISP:</b> {geo_str}\n"
            f"💻 <b>Device Signature:</b> {device_str}\n"
            f"👤 <b>Known Aliases:</b> {', '.join(dossier.aliases_used) or 'None'}\n"
            f"🌐 <b>IPs Utilized:</b> {', '.join(dossier.ips_used) or 'None'}\n"
            f"⏱ <b>Active Window:</b> {dossier.first_seen[11:19]} to {dossier.last_seen[11:19]}\n"
            f"📊 <b>Total Activities:</b> {dossier.total_events} ({dossier.total_messages} messages)\n"
        )

        if dossier.threat.indicators:
            briefing += f"\n⚠️ <b>Detected Attack Signatures:</b>\n"
            for ind, exp in zip(dossier.threat.indicators, dossier.threat.explanations):
                briefing += f"• <code>{ind}</code>: {exp}\n"

        # Generate and upload PDF if requested
        if generate_pdf:
            await status_msg.edit_text(f"📄 <i>Rendering high-resolution forensic PDF dossier...</i>", parse_mode=ParseMode.HTML)
            pdf_path = generate_forensic_pdf(dossier)
            
            with open(pdf_path, "rb") as pdf_file:
                await target_msg.reply_document(
                    document=pdf_file,
                    filename=pdf_path.name,
                    caption=briefing,
                    parse_mode=ParseMode.HTML
                )
            await status_msg.delete()
        else:
            # Inline button to generate PDF
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("📄 Download PDF Dossier", callback_data=f"pdf:{subject_type}:{subject_query}")]
            ])
            await status_msg.edit_text(briefing, parse_mode=ParseMode.HTML, reply_markup=kb)

    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        await status_msg.edit_text(f"⚠️ Error compiling forensic dossier: {e}")

async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    if not context.args:
        await update.message.reply_text(
            "<b>Usage:</b> <code>/report &lt;IP or Username&gt;</code>\n"
            "<i>Example:</i> <code>/report 117.252.20.10</code> or <code>/report alice</code>",
            parse_mode=ParseMode.HTML
        )
        return

    subject = " ".join(context.args).strip()
    await handle_report_generation(update, context, subject, generate_pdf=True)

async def cmd_audit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    if not context.args:
        await update.message.reply_text(
            "<b>Usage:</b> <code>/audit &lt;IP or Username&gt;</code>\n"
            "<i>Example:</i> <code>/audit 117.252.20.10</code>",
            parse_mode=ParseMode.HTML
        )
        return

    subject = " ".join(context.args).strip()
    await handle_report_generation(update, context, subject, generate_pdf=False)

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_authorized(user.id):
        return

    target_msg = update.message or (update.callback_query.message if update.callback_query else None)
    status_msg = await target_msg.reply_text("🔍 <i>Executing live security scan on website audit logs...</i>", parse_mode=ParseMode.HTML)

    try:
        events = collector.fetch_events()
        threat_count = 0
        threat_summary = []

        for ev in events:
            delta, indicators, expls = ThreatDetector.inspect_event(ev)
            if delta > 0:
                threat_count += 1
                threat_summary.append((ev, indicators, delta))

        if threat_count == 0:
            result_text = (
                f"✅ <b>Live Audit Scan Complete:</b>\n\n"
                f"Scanned <b>{len(events)}</b> events across <b>{len(set(e.ip for e in events))}</b> unique IPs.\n"
                f"Zero critical threats, exploits, or malicious payloads detected."
            )
        else:
            lines = [f"🚨 <b>Security Audit Scan Detected {threat_count} Threats!</b>\n"]
            for ev, indicators, delta in threat_summary[:5]:
                lines.append(
                    f"• <b>Subject:</b> <code>{ev.sender}</code> ({ev.ip})\n"
                    f"   <b>Threat:</b> {', '.join(indicators)} (Risk +{delta})\n"
                    f"   <b>Payload:</b> <code>{ev.message[:80]}</code>\n"
                    f"   <b>Report:</b> /report_{ev.ip.replace('.', '_')}\n"
                )
            result_text = "\n".join(lines)

        await status_msg.edit_text(result_text, parse_mode=ParseMode.HTML, reply_markup=get_dashboard_keyboard())
    except Exception as e:
        await status_msg.edit_text(f"⚠️ Error during scan: {e}")

async def cmd_monitor(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global monitoring_active
    user = update.effective_user
    if not is_authorized(user.id):
        return

    if context.args:
        arg = context.args[0].lower()
        if arg in ["on", "start", "enable"]:
            monitoring_active = True
            await update.message.reply_text("🟢 Real-time background audit monitoring <b>ENABLED</b>.", parse_mode=ParseMode.HTML)
        elif arg in ["off", "stop", "disable"]:
            monitoring_active = False
            await update.message.reply_text("🔴 Real-time background audit monitoring <b>PAUSED</b>.", parse_mode=ParseMode.HTML)
        else:
            await update.message.reply_text("Usage: <code>/monitor on</code> or <code>/monitor off</code>", parse_mode=ParseMode.HTML)
    else:
        state = "ENABLED" if monitoring_active else "PAUSED"
        await update.message.reply_text(f"Monitoring is currently <b>{state}</b>.", parse_mode=ParseMode.HTML)

# ----------------- INLINE BUTTON & SHORTCUT HANDLERS ----------------- #

async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
    if data == "btn_status":
        await cmd_status(update, context)
    elif data == "btn_scan":
        await cmd_scan(update, context)
    elif data == "btn_users":
        await cmd_users(update, context)
    elif data == "btn_ips":
        await cmd_ips(update, context)
    elif data == "btn_logs":
        await cmd_logs(update, context)
    elif data.startswith("pdf:"):
        parts = data.split(":", 2)
        if len(parts) == 3:
            subject = parts[2]
            await handle_report_generation(update, context, subject, generate_pdf=True)

async def handle_shortcut_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles shortcuts like /report_117_252_20_10 or /report_alice"""
    cmd = update.message.text.split()[0].replace("/", "")
    if cmd.startswith("report_"):
        raw_val = cmd[7:]
        # If it looks like an IP with underscores, convert back to dots
        if "_" in raw_val and all(p.isdigit() for p in raw_val.split("_")):
            raw_val = raw_val.replace("_", ".")
        await handle_report_generation(update, context, raw_val, generate_pdf=True)

# ----------------- BACKGROUND MONITORING LOOP ----------------- #

async def background_monitoring_worker(app):
    """Runs asynchronously in the background polling for new events and alerting."""
    global active_alert_chat
    logger.info("Background monitoring worker initiated.")
    
    # Baseline existing logs so we don't alert on historical items
    try:
        collector.mark_all_current_as_seen()
        logger.info("Audit log baseline recorded.")
    except Exception as e:
        logger.warning(f"Could not initialize baseline: {e}")

    while True:
        try:
            if monitoring_active and active_alert_chat:
                new_events = collector.poll_new_events()
                for ev in new_events:
                    risk_delta, indicators, expls = ThreatDetector.inspect_event(ev)
                    # Alert if flagged by server OR matched security signatures
                    if risk_delta > 0 or ev.is_flagged or ev.flags:
                        alert_text = (
                            f"🚨 <b>SECURITY ALERT DETECTED</b>\n\n"
                            f"• <b>Subject:</b> <b>{ev.sender}</b>\n"
                            f"• <b>IP Address:</b> <code>{ev.ip}</code>\n"
                            f"• <b>Event Type:</b> <code>{ev.event_type}</code>\n"
                            f"• <b>Risk Score:</b> <b>+{risk_delta}</b>\n"
                            f"• <b>Triggered Rules:</b> {', '.join(indicators) or 'Flagged Event'}\n"
                            f"• <b>Target:</b> <i>{ev.target}</i>\n"
                            f"• <b>Payload:</b> <code>{ev.message}</code>\n"
                            f"• <b>Timestamp:</b> <code>{ev.timestamp}</code>\n"
                        )
                        kb = InlineKeyboardMarkup([
                            [InlineKeyboardButton("📄 Generate Forensic Dossier (PDF)", callback_data=f"pdf:IP:{ev.ip}")]
                        ])
                        await app.bot.send_message(
                            chat_id=active_alert_chat,
                            text=alert_text,
                            parse_mode=ParseMode.HTML,
                            reply_markup=kb
                        )
        except Exception as e:
            logger.error(f"Error in background monitor cycle: {e}")

        await asyncio.sleep(config.POLL_INTERVAL_SECONDS)

async def post_init(application):
    """Starts the background worker once bot is initialized."""
    asyncio.create_task(background_monitoring_worker(application))

def main():
    token = config.TELEGRAM_BOT_TOKEN
    # Clean token from accidental quotes or spaces
    if token:
        token = token.strip().strip("'\"")

    if not token or token == "YOUR_BOTFATHER_TOKEN_HERE":
        print("\n" + "="*65)
        print(" [!] TELEGRAM_BOT_TOKEN is not configured yet!")
        print(" [!] Please obtain a token from @BotFather on Telegram and")
        print(" [!] set it in your environment variables:")
        print("     TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqr...")
        print("="*65 + "\n")
        sys.exit(1)

    # Validate standard Telegram token format: <digits>:<string>
    if ":" not in token or not token.split(":", 1)[0].isdigit():
        print("\n" + "="*65)
        print(" [!] CRITICAL: MALFORMED TELEGRAM_BOT_TOKEN!")
        print(f" [!] Received token: '{token}'")
        print(" [!] A valid Telegram bot token MUST contain two parts separated by a colon (:):")
        print("     Format: <BOT_ID>:<SECRET_KEY>")
        print("     Example: 7891234567:AAHaDeidi_bnyEnGv8K5I3sIzB-ETPy-P60")
        print(" [!] It looks like the numeric Bot ID prefix was omitted or there are accidental spaces.")
        print(" [!] Please go back to @BotFather on Telegram and copy the ENTIRE token line.")
        print("="*65 + "\n")
        sys.exit(1)

    print(f"[*] Starting Pulse Chat Forensic Sentinel Bot...")
    print(f"[*] Monitoring URL: {config.AUDIT_LOGS_URL}")
    print(f"[*] Polling frequency: {config.POLL_INTERVAL_SECONDS} seconds")

    # Start healthcheck server if running on cloud environments with $PORT (e.g. Render)
    start_health_server()

    app = ApplicationBuilder().token(token).post_init(post_init).build()

    # Handlers
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("logs", cmd_logs))
    app.add_handler(CommandHandler("users", cmd_users))
    app.add_handler(CommandHandler("ips", cmd_ips))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("audit", cmd_audit))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("monitor", cmd_monitor))

    # Dynamic shortcut handler for /report_<ip_or_user>
    from telegram.ext import MessageHandler, filters
    app.add_handler(MessageHandler(filters.Regex(r"^/report_"), handle_shortcut_command))
    
    app.add_handler(CallbackQueryHandler(handle_callback_query))

    print("[+] Bot initialized. Listening for Telegram events...")
    app.run_polling()

if __name__ == "__main__":
    main()
