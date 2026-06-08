import time
import base64
import requests
from urllib.parse import urlparse

from config import VT_API_KEY

SAFE_DOMAINS: set[str] = {
    "google.com",
    "notifications.google.com",
    "gmail.com",
    "youtube.com",
    "youtu.be",
    "microsoft.com",
    "office.com",
    "outlook.com",
}


def _get_headers() -> dict:
    return {"x-apikey": VT_API_KEY}


def should_scan_url(url: str) -> bool:
    try:
        domain = urlparse(url).netloc.lower()
        # Strip leading www. only (anchored, not replace-all)
        if domain.startswith("www."):
            domain = domain[4:]

        if domain in SAFE_DOMAINS:
            return False

        # Skip huge tracking URLs
        if len(url) > 300:
            return False

        return True

    except Exception:
        return False


def _submit_url(url: str) -> str | None:
    """Submit a URL to VT for scanning. Returns the analysis ID or None."""
    if not VT_API_KEY:
        return None

    resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=_get_headers(),
        data={"url": url},
        timeout=15,
    )
    if resp.status_code == 200:
        return resp.json()["data"]["id"]
    return None


def _poll_analysis(analysis_id: str, timeout: int = 30) -> dict | None:
    """
    Poll /api/v3/analyses/{id} until status is 'completed' or timeout.
    Returns the stats dict or None.
    """
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(5)
        try:
            resp = requests.get(endpoint, headers=_get_headers(), timeout=10)
            if resp.status_code != 200:
                break
            data = resp.json()["data"]["attributes"]
            if data.get("status") == "completed":
                return data.get("stats")
        except Exception:
            break
    return None


def _fetch_cached_report(url: str) -> dict | None:
    """
    Fetch the historical VT report for a URL by its base64 ID.
    Returns last_analysis_stats or None.
    """
    if not VT_API_KEY:
        return None

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=_get_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception:
        pass
    return None


def _analyze_url(url: str) -> dict | None:
    """Submit URL, poll for fresh result, fall back to cached report."""
    analysis_id = _submit_url(url)

    stats = None
    if analysis_id:
        stats = _poll_analysis(analysis_id)

    if stats is None:
        # Fall back to cached/historical report (URL already known to VT)
        stats = _fetch_cached_report(url)

    if stats is None:
        return None

    return {
        "url": url,
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def scan_url(url: str) -> dict | None:
    from database import get_cached_result, save_result

    if not VT_API_KEY:
        return None

    if not should_scan_url(url):
        print(f"[VT] Skipped safe/tracking URL: {url[:80]}")
        return {"url": url, "skipped": True, "reason": "Trusted or tracking URL"}

    cached = get_cached_result(url)
    if cached:
        print(f"[VT] Cache hit: {url[:80]}")
        return cached

    print(f"[VT] Scanning via API: {url[:80]}")
    result = _analyze_url(url)

    if result:
        result["cached"] = False
        save_result(url, result)
        return result

    return {
        "url":        url,
        "malicious":  0,
        "suspicious": 0,
        "harmless":   0,
        "undetected": 0,
        "cached":     False,
        "error":      "VirusTotal scan failed",
    }
