import sys
import os
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler
import urllib.parse

root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import telegram_api

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Auto-detect host from headers
        host = self.headers.get("Host", "")
        proto = self.headers.get("X-Forwarded-Proto", "https")
        
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        action = params.get("action", ["set"])[0]

        if action == "info":
            info = telegram_api.get_webhook_info()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(info, indent=2).encode('utf-8'))
            return

        # Target webhook url
        custom_url = params.get("url", [None])[0]
        if custom_url:
            target_webhook = custom_url
        else:
            target_webhook = f"{proto}://{host}/api/webhook"

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
