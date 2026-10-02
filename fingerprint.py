from user_agents import parse
from models import VisitorFingerprint

def analyze_user_agent(user_agent_str: str) -> VisitorFingerprint:
    """
    Extracts high-fidelity hardware, OS, and browser fingerprint from a User-Agent string.
    """
    if not user_agent_str or not user_agent_str.strip():
        return VisitorFingerprint(
            raw_user_agent="N/A",
            browser_family="Unknown",
            os_family="Unknown",
            device_family="Unknown",
            confidence="Low"
        )

    try:
        ua = parse(user_agent_str)
        
        browser_family = ua.browser.family
        browser_version = ua.browser.version_string
        os_family = ua.os.family
        os_version = ua.os.version_string
        device_family = ua.device.family

        is_bot = ua.is_bot
        is_mobile = ua.is_mobile
        is_tablet = ua.is_tablet
        is_pc = ua.is_pc

        return VisitorFingerprint(
            raw_user_agent=user_agent_str,
            browser_family=browser_family,
            browser_version=browser_version,
            os_family=os_family,
            os_version=os_version,
            device_family=device_family,
            is_bot=is_bot,
            is_mobile=is_mobile,
            is_tablet=is_tablet,
            is_pc=is_pc,
            confidence="High"
        )
    except Exception:
        return VisitorFingerprint(
            raw_user_agent=user_agent_str,
            browser_family="Raw User-Agent",
            os_family="Unknown",
            confidence="Low"
        )
