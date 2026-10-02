import re
from typing import List, Tuple
from models import AuditEvent, ThreatAssessment

# Compiled security inspection patterns
SQLI_PATTERNS = [
    re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
    re.compile(r"(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)", re.IGNORECASE),
    re.compile(r"(\band\b\s+['\"]?1['\"]?\s*=\s*['\"]?2)", re.IGNORECASE),
    re.compile(r"(;\s*drop\s+table)", re.IGNORECASE),
    re.compile(r"(\binformation_schema\b)", re.IGNORECASE),
    re.compile(r"(\bsleep\s*\(\s*\d+\s*\))", re.IGNORECASE),
    re.compile(r"(\bwaitfor\s+delay\b)", re.IGNORECASE),
    re.compile(r"('|\")\s*--", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"(<\s*script[^>]*>)", re.IGNORECASE),
    re.compile(r"(javascript\s*:)", re.IGNORECASE),
    re.compile(r"(\bonerror\s*=)", re.IGNORECASE),
    re.compile(r"(\bonload\s*=)", re.IGNORECASE),
    re.compile(r"(\bonmouseover\s*=)", re.IGNORECASE),
    re.compile(r"(<\s*img[^>]+src=[^>]+onerror=)", re.IGNORECASE),
    re.compile(r"(<\s*svg[^>]+onload=)", re.IGNORECASE),
    re.compile(r"(document\.cookie)", re.IGNORECASE),
    re.compile(r"(alert\s*\([^)]*\))", re.IGNORECASE),
]

LFI_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\){2,}", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow)", re.IGNORECASE),
    re.compile(r"(/proc/self/)", re.IGNORECASE),
    re.compile(r"(win\.ini|boot\.ini)", re.IGNORECASE),
    re.compile(r"(\.env|config\.json|web\.config)", re.IGNORECASE),
]

RCE_PATTERNS = [
    re.compile(r"(;\s*(cat|ls|id|whoami|uname|curl|wget|bash|sh|powershell)\b)", re.IGNORECASE),
    re.compile(r"(\|\s*(cat|ls|whoami|bash|powershell)\b)", re.IGNORECASE),
    re.compile(r"(&&\s*(whoami|id|cat|curl)\b)", re.IGNORECASE),
    re.compile(r"(\$\(\s*(whoami|id|cat)\s*\))", re.IGNORECASE),
    re.compile(r"(`\s*(whoami|id|cat)\s*`)", re.IGNORECASE),
]

SUSPICIOUS_UA_PATTERNS = [
    re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan)", re.IGNORECASE),
    re.compile(r"(python-requests|aiohttp|urllib|curl|wget|go-http-client|postman)", re.IGNORECASE),
    re.compile(r"(headlesschrome|phantomjs|puppeteer|selenium)", re.IGNORECASE),
]

class ThreatDetector:
    @staticmethod
    def inspect_event(event: AuditEvent) -> Tuple[int, List[str], List[str]]:
        """
        Inspects an individual AuditEvent and returns:
        (risk_delta, indicators, explanations)
        """
        score = 0
        indicators = []
        explanations = []

        content = f"{event.message} {event.sender} {event.target}".strip()

        # 1. Check Server-side Flags
        if event.is_flagged:
            score += 35
            indicators.append("SERVER_FLAGGED")
            explanations.append("The event was explicitly flagged by the website application.")

        for flag in event.flags:
            score += 20
            indicators.append(f"FLAG:{flag.upper()}")
            explanations.append(f"Application security trigger flag: '{flag}'.")

        # 2. Check SQL Injection
        for pat in SQLI_PATTERNS:
            match = pat.search(content)
            if match:
                score += 45
                indicators.append("SQL_INJECTION")
                explanations.append(f"SQL injection syntax detected: '{match.group(0)}'")
                break

        # 3. Check Cross-Site Scripting (XSS)
        for pat in XSS_PATTERNS:
            match = pat.search(content)
            if match:
                score += 40
                indicators.append("XSS_PAYLOAD")
                explanations.append(f"Cross-Site Scripting signature detected: '{match.group(0)}'")
                break

        # 4. Check Local File Inclusion / Path Traversal
        for pat in LFI_PATTERNS:
            match = pat.search(content)
            if match:
                score += 40
                indicators.append("PATH_TRAVERSAL")
                explanations.append(f"Path traversal / sensitive file probe: '{match.group(0)}'")
                break

        # 5. Check Remote Code Execution / Shell Injection
        for pat in RCE_PATTERNS:
            match = pat.search(content)
            if match:
                score += 55
                indicators.append("COMMAND_INJECTION")
                explanations.append(f"Remote command execution pattern: '{match.group(0)}'")
                break

        # 6. Check User Agent
        ua = event.user_agent or ""
        for pat in SUSPICIOUS_UA_PATTERNS:
            match = pat.search(ua)
            if match:
                score += 25
                indicators.append("SUSPICIOUS_CLIENT")
                explanations.append(f"Automated tool or crawler user-agent: '{match.group(0)}'")
                break

        return score, indicators, explanations

    @classmethod
    def evaluate_subject_events(cls, events: List[AuditEvent]) -> ThreatAssessment:
        """
        Aggregates threat analysis across all actions performed by a subject.
        """
        if not events:
            return ThreatAssessment(severity="CLEAN", risk_score=0, indicators=[], explanations=["No activity records found."])

        total_score = 0
        all_indicators = []
        all_explanations = []

        for e in events:
            delta, inds, expls = cls.inspect_event(e)
            total_score += delta
            for ind in inds:
                if ind not in all_indicators:
                    all_indicators.append(ind)
            all_explanations.extend(expls)

        # Cap max score at 100
        final_score = min(100, total_score)

        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 50:
            severity = "HIGH"
        elif final_score >= 25:
            severity = "MEDIUM"
        elif final_score > 0:
            severity = "LOW"
        else:
            severity = "CLEAN"

        return ThreatAssessment(
            severity=severity,
            risk_score=final_score,
            indicators=all_indicators,
            explanations=all_explanations[:10]  # keep top 10 explanations
        )
