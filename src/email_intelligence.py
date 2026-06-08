import re
import ipaddress
import requests

from config import VT_API_KEY


def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY}

# RFC-1918, loopback, link-local — never route to VirusTotal
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def extract_sender_email(email_message) -> str:
    sender = email_message.get("From", "")
    match = re.search(r'<(.+?)>', sender)
    if match:
        return match.group(1).lower()
    return sender.strip().lower()


def extract_sender_domain(sender_email: str) -> str | None:
    if sender_email and "@" in sender_email:
        return sender_email.split("@")[1]
    return None


def extract_sender_ip(email_message) -> str | None:
    """Return the first public IP found in Received headers, or None."""
    for header in email_message.get_all("Received", []):
        match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
        if match:
            ip = match.group(0)
            if _is_public_ip(ip):
                return ip
    return None


def analyze_domain(domain: str) -> dict | None:
    if not VT_API_KEY:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=_vt_headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "domain":     domain,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception:
        return None


def extract_dkim_domain(email_message) -> str | None:
    """Extract DKIM signing domain from Authentication-Results header."""
    auth = email_message.get("Authentication-Results", "")
    match = re.search(r'dkim=pass\s+header\.i=@([\w.\-]+)', auth, re.IGNORECASE)
    return match.group(1).lower().strip() if match else None


def extract_return_path_domain(email_message) -> str | None:
    """Extract domain from Return-Path header."""
    rp = email_message.get("Return-Path", "")
    match = re.search(r'@([\w.\-]+)>', rp)
    return match.group(1).lower().strip() if match else None


def analyze_ip(ip: str) -> dict | None:
    if not VT_API_KEY:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=_vt_headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "ip":         ip,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception:
        return None
