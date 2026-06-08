import re
from bs4 import BeautifulSoup

_URL_RE = re.compile(r'https?://[^\s"<>()]+')


def extract_urls(email_message) -> list[str]:
    """Extract URLs from a parsed email.Message object (all MIME parts)."""
    urls: set[str] = set()

    for part in email_message.walk():
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="ignore")

        if content_type == "text/plain":
            urls.update(_URL_RE.findall(payload))
        elif content_type == "text/html":
            soup = BeautifulSoup(payload, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                if href.startswith(("http://", "https://")):
                    urls.add(href)

    return list(urls)


def extract_urls_from_text(text: str) -> list[str]:
    """
    Extract URLs from a raw string that may be plain text or HTML.
    Combines regex extraction and BeautifulSoup href parsing so that
    URLs inside <a href='...'> attributes are never missed.
    """
    urls: set[str] = set()
    urls.update(_URL_RE.findall(text))

    soup = BeautifulSoup(text, "html.parser")
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if href.startswith(("http://", "https://")):
            urls.add(href)

    return list(urls)
