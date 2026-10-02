from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass
class AuditEvent:
    id: str
    timestamp: str
    event_type: str
    ip: str
    user_agent: str
    socket_id: str
    sender: str
    target: str
    message: str
    is_flagged: bool = False
    flags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        return cls(
            id=str(data.get("id", "")),
            timestamp=str(data.get("timestamp", "")),
            event_type=str(data.get("eventType", "UNKNOWN")),
            ip=str(data.get("ip", "0.0.0.0")),
            user_agent=str(data.get("userAgent", "")),
            socket_id=str(data.get("socketId", "")),
            sender=str(data.get("sender", "anonymous")),
            target=str(data.get("target", "")),
            message=str(data.get("message", "")),
            is_flagged=bool(data.get("isFlagged", False)),
            flags=list(data.get("flags", []) or []),
            raw=data
        )

@dataclass
class ThreatAssessment:
    severity: str  # "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: int  # 0 to 100
    indicators: List[str] = field(default_factory=list)
    explanations: List[str] = field(default_factory=list)

@dataclass
class IPLocationInfo:
    ip: str
    status: str = "unknown"
    country: str = "Unknown"
    country_code: str = ""
    region_name: str = "Unknown"
    city: str = "Unknown"
    zip_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = "Unknown"
    org: str = "Unknown"
    asn: str = "Unknown"
    is_proxy: Optional[bool] = None
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None

@dataclass
class VisitorFingerprint:
    raw_user_agent: str
    browser_family: str = "Unknown"
    browser_version: str = ""
    os_family: str = "Unknown"
    os_version: str = ""
    device_family: str = "Desktop"
    is_bot: bool = False
    is_mobile: bool = False
    is_tablet: bool = False
    is_pc: bool = True
    confidence: str = "High"

@dataclass
class ForensicDossier:
    subject_type: str  # "IP" or "USER"
    subject_value: str
    case_id: str
    generated_at: str
    first_seen: str
    last_seen: str
    total_events: int
    total_messages: int
    aliases_used: List[str]
    ips_used: List[str]
    sockets_used: List[str]
    targets_accessed: List[str]
    events: List[AuditEvent]
    threat: ThreatAssessment
    ip_intel: Optional[IPLocationInfo]
    fingerprint: Optional[VisitorFingerprint]
