import ipaddress
import logging
from typing import Dict, Optional
import requests

from config import ABUSEIPDB_API_KEY
from models import IPLocationInfo

logger = logging.getLogger("audit_bot.ip_intel")

# In-memory cache for IP lookups during the runtime
_IP_CACHE: Dict[str, IPLocationInfo] = {}

def is_private_or_loopback(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False

def lookup_ip_intelligence(ip: str) -> IPLocationInfo:
    """
    Performs network reconnaissance on an IP address:
    - Geolocation (Country, City, Region, Coordinates)
    - Autonomous System & ISP attribution
    - AbuseIPDB reputation check (if key configured)
    """
    clean_ip = ip.strip()
    if clean_ip in _IP_CACHE:
        return _IP_CACHE[clean_ip]

    info = IPLocationInfo(ip=clean_ip)

    # Handle local / private addresses
    if is_private_or_loopback(clean_ip):
        info.status = "private_network"
        info.country = "Local Network (RFC1918)"
        info.isp = "Private Subnet / Loopback"
        info.org = "Internal Infrastructure"
        info.asn = "N/A"
        _IP_CACHE[clean_ip] = info
        return info

    # 1. Geolocation via ip-api
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                info.status = "success"
                info.country = data.get("country", "Unknown")
                info.country_code = data.get("countryCode", "")
                info.region_name = data.get("regionName", "Unknown")
                info.city = data.get("city", "Unknown")
                info.zip_code = data.get("zip", "")
                info.latitude = float(data.get("lat", 0.0))
                info.longitude = float(data.get("lon", 0.0))
                info.timezone = data.get("timezone", "")
                info.isp = data.get("isp", "Unknown")
                info.org = data.get("org", "Unknown")
                info.asn = data.get("as", "Unknown")
            else:
                info.status = "not_found"
    except Exception as e:
        logger.warning(f"Error querying geolocation for {clean_ip}: {e}")
        info.status = "lookup_failed"

    # 2. Threat & Abuse Intelligence via AbuseIPDB
    if ABUSEIPDB_API_KEY:
        try:
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": clean_ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            res = requests.get(abuse_url, headers=headers, params=params, timeout=6)
            if res.status_code == 200:
                abuse_data = res.json().get("data", {})
                info.abuse_confidence_score = abuse_data.get("abuseConfidenceScore")
                info.total_reports = abuse_data.get("totalReports")
                # Tor/VPN flag heuristic
                if abuse_data.get("isTor") or abuse_data.get("isVpn"):
                    info.is_proxy = True
        except Exception as e:
            logger.warning(f"Error querying AbuseIPDB for {clean_ip}: {e}")

    _IP_CACHE[clean_ip] = info
    return info
