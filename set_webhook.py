import sys
import os
import requests
import json
from pathlib import Path

# Add project root to sys.path
root_dir = str(Path(__file__).resolve().parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import config
import telegram_api

def check_or_set_webhook():
    token = config.TELEGRAM_BOT_TOKEN
    print("=" * 60)
    print("  Pulse Chat Forensic Sentinel - Webhook Manager")
    print("=" * 60)

    # 1. Inspect current status from Telegram
    print("\n[*] Querying Telegram getWebhookInfo...")
    info = telegram_api.get_webhook_info()
    print("Telegram Response:")
    print(json.dumps(info, indent=2))

    # 2. Check if user wants to set a webhook
    args = sys.argv[1:]
    target_url = None

    if args:
        target_url = args[0].strip()
    elif len(sys.argv) == 1:
        # Prompt or check pulse-audit-bot.vercel.app
        default_url = "https://pulse-audit-bot.vercel.app/api/webhook"
        ans = input(f"\n[?] Do you want to set webhook to '{default_url}'? (y/n): ").strip().lower()
        if ans in ['y', 'yes']:
            target_url = default_url

    if target_url:
        if not target_url.endswith("/api/webhook"):
            target_url = target_url.rstrip("/") + "/api/webhook"
        print(f"\n[*] Setting Telegram webhook to: {target_url}...")
        res = telegram_api.set_webhook(target_url)
        print("Telegram setWebhook Response:")
        print(json.dumps(res, indent=2))
        
        # Verify
        print("\n[*] Verifying updated webhook info...")
        updated_info = telegram_api.get_webhook_info()
        print(json.dumps(updated_info, indent=2))

if __name__ == "__main__":
    check_or_set_webhook()
