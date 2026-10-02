import os
import sys
from log_collector import LogCollector
from forensics import ForensicInvestigator
from pdf_generator import generate_forensic_pdf

def main():
    print("[*] Initializing LogCollector...")
    collector = LogCollector()
    
    print("[*] Fetching audit logs from Render endpoint...")
    events = collector.fetch_events()
    print(f"[+] Successfully fetched {len(events)} events.")
    
    stats = collector.get_summary_stats()
    print("\n=== AUDIT SUMMARY ===")
    print(f"Total Events: {stats['total_events']}")
    print(f"Unique IPs: {stats['unique_ips']} -> {stats['ip_list']}")
    print(f"Unique Senders: {stats['unique_senders']} -> {stats['sender_list']}")
    print(f"Flagged Events: {stats['flagged_events']}")
    print("=====================\n")

    if not events:
        print("[-] No events found to analyze.")
        return

    # Choose first IP to generate a dossier
    target_ip = events[0].ip
    print(f"[*] Building forensic dossier for IP: {target_ip}...")
    ip_events = collector.get_events_for_ip(target_ip)
    dossier = ForensicInvestigator.build_dossier_from_events(ip_events, subject_type="IP", subject_value=target_ip)

    print("\n--- DOSSIER PREVIEW ---")
    print(f"Case ID: {dossier.case_id}")
    print(f"Severity: {dossier.threat.severity} (Score: {dossier.threat.risk_score}/100)")
    if dossier.ip_intel:
        print(f"Location: {dossier.ip_intel.city}, {dossier.ip_intel.country} ({dossier.ip_intel.isp})")
    if dossier.fingerprint:
        print(f"Device: {dossier.fingerprint.browser_family} on {dossier.fingerprint.os_family}")
    print(f"Aliases Used: {dossier.aliases_used}")
    print(f"Total Actions: {dossier.total_events}")
    print("-----------------------\n")

    print("[*] Rendering forensic PDF report...")
    pdf_path = generate_forensic_pdf(dossier)
    print(f"[+] PDF generated successfully at: {pdf_path}")
    print(f"[+] File size: {os.path.getsize(pdf_path)} bytes")

if __name__ == "__main__":
    main()
