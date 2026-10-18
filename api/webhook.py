import sys
import os
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler

# Add root directory to sys.path so modules can be imported by Vercel Lambda
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import bot_engine

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "online",
            "service": "Pulse Chat Forensic Sentinel (Telegram Webhook)",
            "method": "POST expected from api.telegram.org"
        }).encode('utf-8'))

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
        pass  # Suppress default server log noise
