import sys
import os
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler

root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import config
from log_collector import LogCollector
from detector import ThreatDetector
import telegram_api

collector = LogCollector()

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Executed by Vercel Cron every minute to check for attacks & send alerts."""
        try:
            new_events = collector.poll_new_events()
            alerts_sent = 0

            # If alert chat is configured, send notifications for any violations
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
