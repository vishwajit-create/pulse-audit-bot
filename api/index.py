import sys
import os
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler
import urllib.parse

# Add root directory to sys.path so modules can be imported by Vercel Serverless
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import config
import bot_engine
from log_collector import LogCollector
from detector import ThreatDetector
import telegram_api

collector = LogCollector()

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        # 1. Cron Job: /api/cron
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
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode('utf-8'))
                return

        # 2. Set Webhook: /api/set_webhook
        elif path == "/api/set_webhook":
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

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "webhook_configured": target_webhook,
                "telegram_result": result
            }, indent=2).encode('utf-8'))
            return

        # 3. Webhook Health / Status: /api/webhook or /api or /api/health
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "online",
                "service": "Pulse Chat Forensic Sentinel (Telegram Webhook)",
                "routes": {
                    "webhook": "/api/webhook (POST for Telegram updates)",
                    "cron": "/api/cron (Daily audit scan)",
                    "set_webhook": "/api/set_webhook (Register webhook with Telegram)"
                }
            }, indent=2).encode('utf-8'))
            return

    def do_POST(self):
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
            # Always return 200 to Telegram to prevent retry storms
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode('utf-8'))

    def log_message(self, format, *args):
        pass
