import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Always resolve .env relative to the project root (one level above src/)
load_dotenv(Path(__file__).parent.parent / ".env")

logger = logging.getLogger(__name__)

VT_API_KEY: str | None = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    logger.warning("VT_API_KEY not set — VirusTotal scanning will be skipped.")

IMAP_HOST: str = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
IMAP_USERNAME: str | None = os.getenv("IMAP_USERNAME")
IMAP_PASSWORD: str | None = os.getenv("IMAP_PASSWORD")
IMAP_LIMIT: int = int(os.getenv("IMAP_LIMIT", "10"))

CORS_ORIGINS: list[str] = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
    ).split(",")
    if o.strip()
]
