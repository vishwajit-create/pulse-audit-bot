import html
import logging
from datetime import datetime
from typing import Dict, Any, Optional

import config
from log_collector import LogCollector
from detector import ThreatDetector
from forensics import ForensicInvestigator
from pdf_generator import generate_forensic_pdf
import telegram_api

logger = logging.getLogger("bot_engine")
collector = LogCollector()

def is_authorized(user_id: int) -> bool:
    if not config.ALLOWED_ADMIN_IDS:
        return True
    return user_id in config.ALLOWED_ADMIN_IDS

def get_dashboard_keyboard() -> Dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "📊 Status", "callback_data": "btn_status"},
                {"text": "🔍 Scan Now", "callback_data": "btn_scan"}
            ],
            [
                {"text": "👥 Visitors", "callback_data": "btn_users"},
                {"text": "🌐 IP Catalog", "callback_data": "btn_ips"}
            ],
            [
                {"text": "📜 Recent Logs", "callback_data": "btn_logs"}
            ]
        ]
    }

def handle_report(chat_id: int, subject_query: str, generate_pdf: bool = True):
    """Compiles forensic analysis and delivers text briefing or PDF document."""
    try:
        events = collector.fetch_events()
        is_ip = ("." in subject_query and any(c.isdigit() for c in subject_query))

        if is_ip:
            matched = [e for e in events if e.ip.strip() == subject_query.strip()]
            subject_type = "IP"
        else:
            matched = [e for e in events if e.sender.strip().lower() == subject_query.strip().lower()]
            subject_type = "USER"

        if not matched:
            telegram_api.send_message(
                chat_id,
                f"❌ <b>No audit records found</b> for subject <code>{html.escape(subject_query)}</code>."
            )
            return

        dossier = ForensicInvestigator.build_dossier_from_events(matched, subject_type, subject_query)

        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "CLEAN": "✅"
        }.get(dossier.threat.severity, "ℹ️")

        geo_str = "N/A"
        if dossier.ip_intel and dossier.ip_intel.city != "Unknown":
            geo_str = f"{dossier.ip_intel.city}, {dossier.ip_intel.country} ({dossier.ip_intel.isp})"

        device_str = "N/A"
        if dossier.fingerprint:
            device_str = f"{dossier.fingerprint.browser_family} on {dossier.fingerprint.os_family} ({dossier.fingerprint.device_family})"

        briefing = (
            f"🛡️ <b>FORENSIC INVESTIGATION REPORT</b>\n"
            f"<b>Case Ref:</b> <code>{dossier.case_id}</code>\n"
            f"<b>Target {dossier.subject_type}:</b> <code>{html.escape(dossier.subject_value)}</code>\n"
            f"<b>Threat Status:</b> {severity_emoji} <b>{dossier.threat.severity}</b> ({dossier.threat.risk_score}/100)\n\n"
            f"📍 <b>Location & ISP:</b> {html.escape(geo_str)}\n"
            f"💻 <b>Device Signature:</b> {html.escape(device_str)}\n"
            f"👤 <b>Known Aliases:</b> {html.escape(', '.join(dossier.aliases_used)) or 'None'}\n"
            f"🌐 <b>IPs Utilized:</b> {html.escape(', '.join(dossier.ips_used)) or 'None'}\n"
            f"⏱ <b>Active Window:</b> {dossier.first_seen[11:19]} to {dossier.last_seen[11:19]}\n"
            f"📊 <b>Total Activities:</b> {dossier.total_events} ({dossier.total_messages} messages)\n"
        )

        if dossier.threat.indicators:
            briefing += f"\n⚠️ <b>Detected Attack Signatures:</b>\n"
            for ind, exp in zip(dossier.threat.indicators, dossier.threat.explanations):
                briefing += f"• <code>{html.escape(ind)}</code>: {html.escape(exp)}\n"

        if generate_pdf:
            pdf_path = generate_forensic_pdf(dossier)
            success = telegram_api.send_document(
                chat_id=chat_id,
                file_path=str(pdf_path),
                caption=briefing
            )
            if not success:
                # Fallback to text message if upload fails
                telegram_api.send_message(chat_id, briefing)
        else:
            kb = {
                "inline_keyboard": [
                    [{"text": "📄 Download PDF Dossier", "callback_data": f"pdf:{subject_type}:{subject_query}"}]
                ]
            }
            telegram_api.send_message(chat_id, briefing, reply_markup=kb)

    except Exception as e:
        logger.error(f"Error compiling forensic report: {e}", exc_info=True)
        telegram_api.send_message(chat_id, f"⚠️ Error compiling forensic dossier: {html.escape(str(e))}")

def handle_status(chat_id: int):
    try:
        stats = collector.get_summary_stats()
        text = (
            f"📊 <b>System Telemetry & Status</b>\n\n"
            f"• <b>Platform:</b> Vercel Serverless (Supabase)\n"
            f"• <b>Total Events Indexed:</b> {stats['total_events']}\n"
            f"• <b>Unique IPs Tracked:</b> {stats['unique_ips']}\n"
            f"• <b>Unique Visitor Handles:</b> {stats['unique_senders']}\n"
            f"• <b>Flagged Anomalies:</b> {stats['flagged_events']}\n"
            f"• <b>Monitored Website:</b> {config.VERCEL_APP_URL}\n"
            f"• <b>Checked:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )
        telegram_api.send_message(chat_id, text, reply_markup=get_dashboard_keyboard())
    except Exception as e:
        telegram_api.send_message(chat_id, f"⚠️ Failed to query telemetry: {html.escape(str(e))}")

def handle_logs(chat_id: int, count: int = 5):
    try:
        events = collector.fetch_events()
        recent = events[-count:]
        if not recent:
            telegram_api.send_message(chat_id, "No audit logs recorded yet in database.")
            return

        lines = [f"📜 <b>Recent Audit Events (Last {len(recent)}):</b>\n"]
        for ev in recent:
            flag_badge = "🚩 " if (ev.is_flagged or ev.flags) else ""
            lines.append(
                f"• <b>[{ev.timestamp[11:19]}]</b> {flag_badge}<b>{html.escape(ev.sender)}</b> ({ev.event_type})\n"
                f"   Target: <i>{html.escape(ev.target)}</i> | IP: <code>{ev.ip}</code>\n"
                f"   Payload: <code>{html.escape(ev.message[:80])}</code>\n"
            )
        telegram_api.send_message(chat_id, "\n".join(lines))
    except Exception as e:
        telegram_api.send_message(chat_id, f"⚠️ Error fetching logs: {html.escape(str(e))}")

def handle_users(chat_id: int):
    try:
        events = collector.fetch_events()
        user_map = {}
        for ev in events:
            sender = ev.sender or "anonymous"
            if sender not in user_map:
                user_map[sender] = {"count": 0, "ips": set(), "flagged": 0}
            user_map[sender]["count"] += 1
            if ev.ip and ev.ip != "N/A":
                user_map[sender]["ips"].add(ev.ip)
            if ev.is_flagged or ev.flags:
                user_map[sender]["flagged"] += 1

        lines = ["👥 <b>Observed Visitor Handles (Vercel):</b>\n"]
        for sender, data in sorted(user_map.items(), key=lambda x: x[1]["count"], reverse=True)[:20]:
            flag_str = f" | 🚩 Flags: {data['flagged']}" if data['flagged'] else ""
            lines.append(
                f"• <b>{html.escape(sender)}</b> ({data['count']} events{flag_str})\n"
                f"   Audit: /report_{sender.replace(' ', '_')}\n"
            )
        telegram_api.send_message(chat_id, "\n".join(lines))
    except Exception as e:
        telegram_api.send_message(chat_id, f"⚠️ Error aggregating users: {html.escape(str(e))}")

def handle_ips(chat_id: int):
    try:
        events = collector.fetch_events()
        ip_map = {}
        for ev in events:
            ip = ev.ip or "N/A"
            if ip not in ip_map:
                ip_map[ip] = {"count": 0, "senders": set()}
            ip_map[ip]["count"] += 1
            if ev.sender:
                ip_map[ip]["senders"].add(ev.sender)

        lines = ["🌐 <b>Observed IP Addresses:</b>\n"]
        for ip, data in sorted(ip_map.items(), key=lambda x: x[1]["count"], reverse=True)[:15]:
            senders_str = ", ".join(list(data["senders"])[:3])
            lines.append(
                f"• <code>{ip}</code> ({data['count']} events)\n"
                f"   Aliases: <i>{html.escape(senders_str)}</i>\n"
            )
        telegram_api.send_message(chat_id, "\n".join(lines))
    except Exception as e:
        telegram_api.send_message(chat_id, f"⚠️ Error aggregating IPs: {html.escape(str(e))}")

def handle_scan(chat_id: int):
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
            result = (
                f"✅ <b>Live Audit Scan Complete:</b>\n\n"
                f"Scanned <b>{len(events)}</b> events from Vercel Supabase database.\n"
                f"Zero critical threats, exploits, or malicious payloads detected."
            )
        else:
            lines = [f"🚨 <b>Audit Scan Detected {threat_count} Anomalies!</b>\n"]
            for ev, indicators, delta in threat_summary[:5]:
                lines.append(
                    f"• <b>Subject:</b> <code>{html.escape(ev.sender)}</code> ({ev.ip})\n"
                    f"   <b>Threat:</b> {', '.join(indicators)} (Risk +{delta})\n"
                    f"   <b>Payload:</b> <code>{html.escape(ev.message[:80])}</code>\n"
                )
            result = "\n".join(lines)

        telegram_api.send_message(chat_id, result, reply_markup=get_dashboard_keyboard())
    except Exception as e:
        telegram_api.send_message(chat_id, f"⚠️ Error during scan: {html.escape(str(e))}")

def process_telegram_update(update: Dict[str, Any]):
    """Main entrypoint for processing any incoming Telegram Webhook payload."""
    # 1. Handle Inline Button Callbacks
    if "callback_query" in update:
        cq = update["callback_query"]
        cq_id = cq["id"]
        chat_id = cq["message"]["chat"]["id"]
        from_user = cq["from"]
        data = cq.get("data", "")

        telegram_api.answer_callback(cq_id)

        if not is_authorized(from_user["id"]):
            telegram_api.send_message(chat_id, "⛔ Access Denied.")
            return

        if data == "btn_status":
            handle_status(chat_id)
        elif data == "btn_scan":
            handle_scan(chat_id)
        elif data == "btn_users":
            handle_users(chat_id)
        elif data == "btn_ips":
            handle_ips(chat_id)
        elif data == "btn_logs":
            handle_logs(chat_id, 5)
        elif data.startswith("pdf:"):
            parts = data.split(":", 2)
            if len(parts) == 3:
                handle_report(chat_id, parts[2], generate_pdf=True)
        return

    # 2. Handle Text Messages / Commands
    if "message" in update and "text" in update["message"]:
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        user_id = msg["from"]["id"]
        text = msg["text"].strip()
        first_name = msg["from"].get("first_name", "Admin")

        if not is_authorized(user_id):
            telegram_api.send_message(chat_id, "⛔ Access Denied: Unauthorized Telegram User.")
            return

        cmd = text.split()[0].lower()
        args = text.split()[1:]

        if cmd in ["/start", "/help"]:
            welcome = (
                f"🛡️ <b>Pulse Chat Forensic Sentinel (Vercel)</b>\n\n"
                f"Welcome, <b>{html.escape(first_name)}</b>!\n"
                f"This bot is actively monitoring your Vercel website audit logs:\n"
                f"<code>{config.VERCEL_APP_URL}</code>\n\n"
                f"<b>Available Commands:</b>\n"
                f"• <code>/status</code> - View monitoring & sync statistics\n"
                f"• <code>/logs [count]</code> - Inspect recent website audit logs\n"
                f"• <code>/users</code> - List all observed visitor usernames\n"
                f"• <code>/ips</code> - List all tracked IP addresses\n"
                f"• <code>/audit &lt;Username or IP&gt;</code> - Instant threat briefing\n"
                f"• <code>/report &lt;Username or IP&gt;</code> - Generate & send full PDF Dossier\n"
                f"• <code>/scan</code> - Run an immediate manual security audit\n"
            )
            telegram_api.send_message(chat_id, welcome, reply_markup=get_dashboard_keyboard())

        elif cmd == "/status":
            handle_status(chat_id)

        elif cmd == "/logs":
            count = int(args[0]) if (args and args[0].isdigit()) else 5
            handle_logs(chat_id, min(15, max(1, count)))

        elif cmd == "/users":
            handle_users(chat_id)

        elif cmd == "/ips":
            handle_ips(chat_id)

        elif cmd == "/audit":
            if not args:
                telegram_api.send_message(chat_id, "Usage: <code>/audit &lt;Username or IP&gt;</code>\nExample: <code>/audit kj</code>")
            else:
                handle_report(chat_id, " ".join(args), generate_pdf=False)

        elif cmd == "/report":
            if not args:
                telegram_api.send_message(chat_id, "Usage: <code>/report &lt;Username or IP&gt;</code>\nExample: <code>/report kj</code>")
            else:
                handle_report(chat_id, " ".join(args), generate_pdf=True)

        elif cmd.startswith("/report_"):
            target = cmd[8:].replace("_", " ")
            handle_report(chat_id, target, generate_pdf=True)

        elif cmd == "/scan":
            handle_scan(chat_id)
