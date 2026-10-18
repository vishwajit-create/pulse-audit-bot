import sys
import os
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler
import urllib.parse

root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import config
import bot_engine
import telegram_api
from log_collector import LogCollector
from detector import ThreatDetector

collector = LogCollector()

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle incoming webhook posts even if routed to index."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8')
                update = json.loads(body)
                bot_engine.process_telegram_update(update)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode('utf-8'))
        except Exception as e:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode('utf-8'))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        # 1. Route to Webhook Info
        if path == "/api/webhook":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "online",
                "service": "Pulse Chat Forensic Sentinel (Telegram Webhook)",
                "method": "POST expected from api.telegram.org"
            }).encode('utf-8'))
            return

        # 2. Route to Cron Check
        if path == "/api/cron":
            try:
                new_events = collector.poll_new_events()
                alerts_sent = 0
                if config.ALERT_CHAT_ID and new_events:
                    for ev in new_events:
                        risk_delta, indicators, expls = ThreatDetector.inspect_event(ev)
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
                            kb = {
                                "inline_keyboard": [
                                    [{"text": "📄 Generate Forensic Dossier (PDF)", "callback_data": f"pdf:USER:{ev.sender}"}]
                                ]
                            }
                            telegram_api.send_message(
                                chat_id=config.ALERT_CHAT_ID,
                                text=alert_text,
                                reply_markup=kb
                            )
                            alerts_sent += 1

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "ok": True,
                    "events_checked": len(new_events),
                    "threat_alerts_sent": alerts_sent,
                    "status": "Audit monitoring cycle complete"
                }).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode('utf-8'))
            return

        # 3. Route to Webhook Registration
        if path == "/api/set_webhook":
            host = self.headers.get("Host", "")
            proto = self.headers.get("X-Forwarded-Proto", "https")
            params = urllib.parse.parse_qs(parsed.query)
            action = params.get("action", ["set"])[0]

            if action == "info":
                info = telegram_api.get_webhook_info()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(info, indent=2).encode('utf-8'))
                return

            custom_url = params.get("url", [None])[0]
            target_webhook = custom_url if custom_url else f"{proto}://{host}/api/webhook"
            result = telegram_api.set_webhook(target_webhook)

            html_resp = f"""<!DOCTYPE html>
<html>
<head>
    <title>Telegram Webhook Setup</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; text-align: center; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 30px; max-width: 600px; margin: 0 auto; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h1 {{ color: #38bdf8; font-size: 24px; }}
        pre {{ background: #0b0f19; padding: 15px; border-radius: 8px; text-align: left; overflow-x: auto; color: #4ade80; }}
        a {{ color: #38bdf8; text-decoration: none; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ Telegram Webhook Registered</h1>
        <p>Configured Webhook URL:</p>
        <code>{target_webhook}</code>
        <p>Telegram Response:</p>
        <pre>{json.dumps(result, indent=2)}</pre>
        <p><a href="/api/set_webhook?action=info">Inspect Webhook Info</a> | <a href="/">Return Home</a></p>
    </div>
</body>
</html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_resp.encode('utf-8'))
            return

        # 4. Default: Show Interactive Web Dashboard
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pulse Chat Forensic Sentinel - Vercel Serverless</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0b0f19;
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 16px;
            padding: 40px;
            max-width: 650px;
            width: 90%;
            box-shadow: 0 20px 40px rgba(0,0,0,0.6);
            text-align: center;
        }}
        .badge {{
            display: inline-block;
            background: #065f46;
            color: #34d399;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 20px;
        }}
        h1 {{
            font-size: 26px;
            margin: 0 0 10px 0;
            color: #38bdf8;
        }}
        p {{
            color: #94a3b8;
            font-size: 15px;
            line-height: 1.6;
        }}
        .info-box {{
            background: #1e293b;
            border-radius: 10px;
            padding: 16px;
            margin: 25px 0;
            text-align: left;
            font-size: 14px;
            color: #cbd5e1;
        }}
        .info-row {{
            margin: 8px 0;
        }}
        .info-row b {{
            color: #e2e8f0;
        }}
        .btn {{
            display: inline-block;
            background: #2563eb;
            color: #ffffff;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            margin: 6px;
            transition: background 0.2s;
        }}
        .btn:hover {{
            background: #1d4ed8;
        }}
        .btn-secondary {{
            background: #334155;
        }}
        .btn-secondary:hover {{
            background: #475569;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="badge">🟢 Vercel Serverless Ready</div>
        <h1>🛡️ Pulse Chat Forensic Sentinel</h1>
        <p>Continuous AI-assisted cyber-forensic monitoring for your Vercel web application.</p>

        <div class="info-box">
            <div class="info-row"><b>Website Monitored:</b> <a href="{config.VERCEL_APP_URL}" target="_blank" style="color:#38bdf8;">{config.VERCEL_APP_URL}</a></div>
            <div class="info-row"><b>Database Engine:</b> Supabase Realtime ({config.SUPABASE_TABLE})</div>
            <div class="info-row"><b>Webhook Route:</b> <code>/api/webhook</code></div>
            <div class="info-row"><b>Cron Route:</b> <code>/api/cron</code> (Daily)</div>
        </div>

        <div>
            <a href="/api/set_webhook" class="btn">⚡ 1-Click Register Webhook</a>
            <a href="/api/set_webhook?action=info" class="btn btn-secondary">🔍 Webhook Health</a>
        </div>
    </div>
</body>
</html>"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
