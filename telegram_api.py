import os
import logging
from typing import Optional, Dict, Any
import requests

from config import TELEGRAM_BOT_TOKEN

logger = logging.getLogger("telegram_api")

def get_base_url() -> str:
    token = TELEGRAM_BOT_TOKEN.strip().strip("'\"")
    return f"https://api.telegram.org/bot{token}"

def send_message(chat_id: int, text: str, parse_mode: str = "HTML", reply_markup: Optional[Dict[str, Any]] = None) -> bool:
    """Send an HTML-formatted message to a Telegram chat."""
    url = f"{get_base_url()}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup

    try:
        res = requests.post(url, json=payload, timeout=10)
        return res.status_code == 200
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")
        return False

def send_document(chat_id: int, file_path: str, caption: str = "", parse_mode: str = "HTML") -> bool:
    """Upload and deliver a forensic PDF report directly to Telegram chat."""
    url = f"{get_base_url()}/sendDocument"
    data = {
        "chat_id": chat_id,
        "caption": caption,
        "parse_mode": parse_mode
    }
    try:
        with open(file_path, "rb") as f:
            files = {"document": f}
            res = requests.post(url, data=data, files=files, timeout=30)
            return res.status_code == 200
    except Exception as e:
        logger.error(f"Failed to upload document to Telegram: {e}")
        return False

def answer_callback(callback_query_id: str, text: Optional[str] = None) -> bool:
    """Acknowledge an inline keyboard button press."""
    url = f"{get_base_url()}/answerCallbackQuery"
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    try:
        requests.post(url, json=payload, timeout=5)
        return True
    except Exception:
        return False

def set_webhook(webhook_url: str) -> Dict[str, Any]:
    """Register the Vercel webhook URL with Telegram."""
    url = f"{get_base_url()}/setWebhook"
    try:
        res = requests.post(url, json={"url": webhook_url}, timeout=10)
        return res.json()
    except Exception as e:
        return {"ok": False, "description": str(e)}

def get_webhook_info() -> Dict[str, Any]:
    """Inspect current Telegram webhook status."""
    url = f"{get_base_url()}/getWebhookInfo"
    try:
        res = requests.get(url, timeout=10)
        return res.json()
    except Exception as e:
        return {"ok": False, "description": str(e)}
