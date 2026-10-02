import uuid
from datetime import datetime
from typing import List, Optional

from models import AuditEvent, ForensicDossier
from detector import ThreatDetector
from ip_intel import lookup_ip_intelligence
from fingerprint import analyze_user_agent

class ForensicInvestigator:
    @staticmethod
    def build_dossier_from_events(
        events: List[AuditEvent],
        subject_type: str,
        subject_value: str
    ) -> ForensicDossier:
        """
        Synthesizes a full forensic dossier from a collection of audit events.
        """
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        if not events:
            # Empty dossier
            return ForensicDossier(
                subject_type=subject_type,
                subject_value=subject_value,
                case_id=case_id,
                generated_at=generated_at,
                first_seen="N/A",
                last_seen="N/A",
                total_events=0,
                total_messages=0,
                aliases_used=[],
                ips_used=[],
                sockets_used=[],
                targets_accessed=[],
                events=[],
                threat=ThreatDetector.evaluate_subject_events([]),
                ip_intel=None,
                fingerprint=None
            )

        # Sort events chronologically
        events.sort(key=lambda x: x.timestamp)

        first_seen = events[0].timestamp
        last_seen = events[-1].timestamp
        total_events = len(events)
        total_messages = sum(1 for e in events if e.event_type.upper() == "MESSAGE")

        aliases = sorted(list(set(e.sender for e in events if e.sender)))
        ips = sorted(list(set(e.ip for e in events if e.ip)))
        sockets = sorted(list(set(e.socket_id for e in events if e.socket_id)))
        targets = sorted(list(set(e.target for e in events if e.target)))

        # Evaluate threat & attack signatures
        threat = ThreatDetector.evaluate_subject_events(events)

        # Network Recon: Use the primary IP
        primary_ip = subject_value if subject_type == "IP" else (ips[0] if ips else "")
        ip_intel = lookup_ip_intelligence(primary_ip) if primary_ip else None

        # Device Fingerprint: Use the latest User-Agent recorded
        latest_ua = ""
        for e in reversed(events):
            if e.user_agent:
                latest_ua = e.user_agent
                break
        fingerprint = analyze_user_agent(latest_ua) if latest_ua else None

        return ForensicDossier(
            subject_type=subject_type,
            subject_value=subject_value,
            case_id=case_id,
            generated_at=generated_at,
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=total_events,
            total_messages=total_messages,
            aliases_used=aliases,
            ips_used=ips,
            sockets_used=sockets,
            targets_accessed=targets,
            events=events,
            threat=threat,
            ip_intel=ip_intel,
            fingerprint=fingerprint
        )
