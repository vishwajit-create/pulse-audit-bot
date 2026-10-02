import json
import logging
from typing import List, Dict, Any, Tuple
import requests

from config import AUDIT_LOGS_URL, STATE_FILE
from models import AuditEvent

logger = logging.getLogger("audit_bot.collector")

class LogCollector:
    def __init__(self, url: str = AUDIT_LOGS_URL):
        self.url = url
        self.seen_event_ids = self._load_seen_ids()

    def _load_seen_ids(self) -> set:
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return set(data.get("seen_ids", []))
            except Exception as e:
                logger.warning(f"Error loading seen events state: {e}")
        return set()

    def _save_seen_ids(self):
        try:
            # Keep only the last 2000 seen event IDs to prevent unbounded state growth
            trimmed_ids = list(self.seen_event_ids)[-2000:]
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({"seen_ids": trimmed_ids}, f, indent=2)
        except Exception as e:
            logger.warning(f"Error saving seen events state: {e}")

    def fetch_events(self) -> List[AuditEvent]:
        """Fetch audit events from the configured Render admin endpoint."""
        try:
            resp = requests.get(self.url, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            raw_logs = data.get("logs", [])
            events = [AuditEvent.from_dict(item) for item in raw_logs]
            # Order from oldest to newest by timestamp if possible
            events.sort(key=lambda x: x.timestamp)
            return events
        except Exception as e:
            logger.error(f"Failed to fetch audit logs from {self.url}: {e}")
            raise

    def poll_new_events(self) -> List[AuditEvent]:
        """Poll the endpoint and return only newly discovered events since last poll."""
        all_events = self.fetch_events()
        new_events = []
        for evt in all_events:
            if evt.id and evt.id not in self.seen_event_ids:
                new_events.append(evt)
                self.seen_event_ids.add(evt.id)
            elif not evt.id:
                # If event has no id, use hash of timestamp + ip + message
                pseudo_id = f"{evt.timestamp}_{evt.ip}_{evt.message[:20]}"
                if pseudo_id not in self.seen_event_ids:
                    new_events.append(evt)
                    self.seen_event_ids.add(pseudo_id)
        
        if new_events:
            self._save_seen_ids()
        return new_events

    def mark_all_current_as_seen(self):
        """Mark existing events as seen so we don't alert retroactively on bot start."""
        try:
            events = self.fetch_events()
            for evt in events:
                if evt.id:
                    self.seen_event_ids.add(evt.id)
            self._save_seen_ids()
        except Exception as e:
            logger.warning(f"Could not initialize seen events baseline: {e}")

    def get_events_for_ip(self, ip: str) -> List[AuditEvent]:
        events = self.fetch_events()
        return [e for e in events if e.ip.strip() == ip.strip()]

    def get_events_for_user(self, username: str) -> List[AuditEvent]:
        events = self.fetch_events()
        return [e for e in events if e.sender.strip().lower() == username.strip().lower()]

    def get_summary_stats(self) -> Dict[str, Any]:
        events = self.fetch_events()
        unique_ips = set(e.ip for e in events if e.ip)
        unique_senders = set(e.sender for e in events if e.sender)
        flagged_count = sum(1 for e in events if e.is_flagged or e.flags)
        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "unique_senders": len(unique_senders),
            "flagged_events": flagged_count,
            "ip_list": list(unique_ips),
            "sender_list": list(unique_senders)
        }
