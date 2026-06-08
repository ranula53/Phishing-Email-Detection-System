import re
from email.header import decode_header
from bs4 import BeautifulSoup

TOPIC_KEYWORDS: dict[str, list[str]] = {
    "Billing & Finance":      ["invoice", "billing", "payment", "receipt"],
    "Account Security":       ["password", "security", "account", "login", "verify"],
    "Marketing & Promotions": ["offer", "discount", "promo", "deal", "free"],
    "Urgent Action":          ["urgent", "action required", "immediate"],
}


def decode_subject(raw_subject) -> str:
    if not raw_subject:
        return ""
    decoded, encoding = decode_header(raw_subject)[0]
    if isinstance(decoded, bytes):
        return decoded.decode(encoding or "utf-8", errors="ignore")
    return decoded or ""


def parse_sender(sender_raw: str) -> tuple[str, str]:
    """Returns (display_name, email_address)."""
    if not sender_raw:
        return "", ""
    match = re.search(r'(.*?)\s*<(.+?)>', sender_raw)
    if match:
        return match.group(1).strip(' \t"\''), match.group(2).strip()
    return "", sender_raw.strip()


def extract_body(msg) -> str:
    """Extract readable plain text from an email.Message object."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            payload_bytes = part.get_payload(decode=True)
            if not payload_bytes:
                continue
            payload_str = payload_bytes.decode("utf-8", errors="ignore")
            if content_type == "text/plain":
                body += payload_str + "\n"
            elif content_type == "text/html":
                body += BeautifulSoup(payload_str, "html.parser").get_text(separator=" ") + "\n"
    else:
        # decode=True works for email.message_from_bytes; for message_from_string
        # without a Content-Transfer-Encoding header it returns None, so fall back.
        payload_bytes = msg.get_payload(decode=True)
        if payload_bytes:
            payload_str = payload_bytes.decode("utf-8", errors="ignore")
        else:
            payload_str = msg.get_payload() or ""

        content_type = msg.get_content_type()
        # Strip HTML tags if the payload is HTML, even if content-type says text/plain
        if content_type == "text/html" or (
            payload_str and "<html" in payload_str.lower()[:200]
        ):
            body = BeautifulSoup(payload_str, "html.parser").get_text(separator=" ")
        else:
            body = payload_str

    return body


def classify_topic(text: str) -> str:
    lower = text.lower()
    for topic, keywords in TOPIC_KEYWORDS.items():
        if any(k in lower for k in keywords):
            return topic
    return "General"
