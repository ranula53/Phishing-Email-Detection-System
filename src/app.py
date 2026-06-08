import re
import email
import imaplib
import threading
import time
from collections import deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import torch
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from transformers import BertTokenizer, BertForSequenceClassification

from config import (
    CORS_ORIGINS,
    IMAP_HOST, IMAP_PORT, IMAP_USERNAME, IMAP_PASSWORD, IMAP_LIMIT,
)
from database import init_db, is_email_scanned, save_scanned_email
from email_intelligence import (
    extract_sender_email,
    extract_sender_domain,
    extract_sender_ip,
    analyze_domain,
    analyze_ip,
    extract_dkim_domain,
    extract_return_path_domain,
)
from email_parser import decode_subject, parse_sender, extract_body, classify_topic
from url_extractor import extract_urls, extract_urls_from_text
from virustotal_api import scan_url
from model_fix import adjust_for_reputation

# ─────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────

APP_START_TIME = datetime.now(timezone.utc)

# Bounded deque: auto-drops oldest entries after 500; append is GIL-atomic.
# The lock protects the snapshot read in the endpoint so count == len(emails).
_auto_scan_results: deque = deque(maxlen=500)
_results_lock = threading.Lock()

app = FastAPI(title="Phishing Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()
    threading.Thread(target=auto_scan_loop, daemon=True).start()


# ─────────────────────────────────────────────────────────────
# LOAD MODEL
# ─────────────────────────────────────────────────────────────

MODEL_PATH = "../models/phishing_model_v3"

print("Loading model...")
tokenizer = BertTokenizer.from_pretrained(MODEL_PATH)
model = BertForSequenceClassification.from_pretrained(MODEL_PATH)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()
print(f"Model loaded on {device}")


# ─────────────────────────────────────────────────────────────
# REQUEST SCHEMAS
# ─────────────────────────────────────────────────────────────

class EmailInput(BaseModel):
    text: str


class IMAPConfig(BaseModel):
    host:     str = Field(default=IMAP_HOST)
    port:     int = Field(default=IMAP_PORT)
    username: str = Field(default="")
    password: str = Field(default="")
    limit:    int = Field(default=5, ge=1, le=50)


# ─────────────────────────────────────────────────────────────
# BERT PREDICTION
# ─────────────────────────────────────────────────────────────

def predict(text: str) -> dict:
    inputs = tokenizer(
        text.lower(),
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512,
    ).to(device)

    with torch.no_grad():
        outputs = model(**inputs)

    probabilities = torch.softmax(outputs.logits, dim=1)
    prediction    = torch.argmax(probabilities, dim=1).item()
    confidence    = probabilities[0][prediction].item() * 100
    phishing_score = probabilities[0][1].item() * 100

    return {
        "label":         "Phishing" if prediction == 1 else "Legitimate",
        "is_phishing":   prediction == 1,
        "confidence":    round(confidence, 2),
        "phishing_score": round(phishing_score, 2),
        "safe_score":    round(100 - phishing_score, 2),
    }


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _to_utc_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _gather_intelligence(msg, raw_text: str) -> dict:
    """Collect VT/domain/IP intelligence for a single email."""
    sender_email       = extract_sender_email(msg)
    sender_domain      = extract_sender_domain(sender_email) if sender_email else None
    sender_ip          = extract_sender_ip(msg)
    dkim_domain        = extract_dkim_domain(msg)
    return_path_domain = extract_return_path_domain(msg)

    domain_result = analyze_domain(sender_domain) if sender_domain else None
    ip_result     = analyze_ip(sender_ip) if sender_ip else None

    urls = set(extract_urls(msg)) | set(extract_urls_from_text(raw_text))
    vt_results = [r for url in urls if (r := scan_url(url)) is not None]

    return {
        "sender_email":         sender_email,
        "sender_domain_result": domain_result,
        "sender_ip_result":     ip_result,
        "dkim_domain":          dkim_domain,
        "return_path_domain":   return_path_domain,
        "virustotal":           vt_results,
    }


# ─────────────────────────────────────────────────────────────
# ROUTES — status
# ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "Phishing Detection API is running"}


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_PATH, "device": str(device)}


@app.get("/auto-scan-results")
def get_auto_scan_results():
    with _results_lock:
        snapshot = list(_auto_scan_results)
    return {"count": len(snapshot), "emails": snapshot[-50:]}


# ─────────────────────────────────────────────────────────────
# SINGLE EMAIL SCAN
# ─────────────────────────────────────────────────────────────

@app.post("/predict")
def predict_email(payload: EmailInput):
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="Email text cannot be empty")

    raw_text = payload.text

    # Parse RFC 2822 headers from the raw text BEFORE any HTML stripping
    msg = email.message_from_string(raw_text)
    subject    = decode_subject(msg.get("Subject"))
    sender_raw = msg.get("From", "")

    # Regex fallback for plain-text inputs that look like email headers
    if not subject:
        m = re.search(r'(?i)^Subject:\s*(.*)', raw_text, re.MULTILINE)
        if m:
            subject = m.group(1).strip()
    if not sender_raw:
        m = re.search(r'(?i)^From:\s*(.*)', raw_text, re.MULTILINE)
        if m:
            sender_raw = m.group(1).strip()

    display_name, sender_email = parse_sender(sender_raw)

    # Extract readable body for AI prediction
    body  = extract_body(msg) or BeautifulSoup(raw_text, "html.parser").get_text(separator="\n")
    topic = classify_topic(body)

    result = predict(body)
    result.update({
        "timestamp":    datetime.now().isoformat(),
        "subject":      subject or None,
        "sender":       sender_email or None,
        "display_name": display_name or None,
        "topic":        topic,
    })
    intel = _gather_intelligence(msg, raw_text)
    result.update(intel)

    # Preserve raw model output before reputation adjustment
    result["raw_phishing_score"] = result["phishing_score"]
    result["raw_safe_score"]     = result["safe_score"]
    result["raw_label"]          = result["label"]
    result["raw_is_phishing"]    = result["is_phishing"]
    result["raw_confidence"]     = result["confidence"]

    result = adjust_for_reputation(
        result,
        intel["sender_email"],
        intel["sender_domain_result"],
        intel["sender_ip_result"],
        intel.get("dkim_domain"),
        intel.get("return_path_domain"),
        display_name=display_name,
        subject=subject,
    )
    return result


# ─────────────────────────────────────────────────────────────
# INBOX SCAN
# ─────────────────────────────────────────────────────────────

@app.post("/scan-inbox")
def scan_inbox(config: IMAPConfig):
    if not config.username or not config.password:
        raise HTTPException(status_code=400, detail="IMAP username and password are required")

    results = []
    mail = None
    try:
        mail = imaplib.IMAP4_SSL(config.host, config.port, timeout=15)
        mail.login(config.username, config.password)
        mail.select("inbox")

        _, message_data = mail.uid("search", None, "UNSEEN")
        uids        = message_data[0].split()
        recent_uids = uids[-config.limit:]

        for uid in reversed(recent_uids):
            # BODY.PEEK[] fetches the full message WITHOUT marking it as \Seen
            _, msg_data = mail.uid("fetch", uid, "(BODY.PEEK[])")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject      = decode_subject(msg.get("Subject"))
            sender_raw   = msg.get("From", "")
            display_name, sender = parse_sender(sender_raw)
            body         = extract_body(msg)
            topic        = classify_topic(body)
            prediction   = predict(f"{subject} {body}")
            intel        = _gather_intelligence(msg, body)
            prediction["raw_phishing_score"] = prediction["phishing_score"]
            prediction["raw_safe_score"]     = prediction["safe_score"]
            prediction["raw_label"]          = prediction["label"]
            prediction["raw_is_phishing"]    = prediction["is_phishing"]
            prediction["raw_confidence"]     = prediction["confidence"]
            prediction   = adjust_for_reputation(
                prediction,
                intel["sender_email"],
                intel.get("sender_domain_result"),
                intel.get("sender_ip_result"),
                intel.get("dkim_domain"),
                intel.get("return_path_domain"),
                display_name=display_name,
                subject=subject,
            )

            results.append({
                "subject":      subject or None,
                "sender":       sender or None,
                "display_name": display_name or None,
                "topic":        topic,
                "prediction":   prediction,
                "timestamp":    datetime.now().isoformat(),
                **intel,
            })

    except imaplib.IMAP4.error as e:
        raise HTTPException(status_code=401, detail=f"IMAP login failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        if mail:
            try:
                mail.logout()
            except Exception:
                pass

    total    = len(results)
    phishing = sum(1 for r in results if r["prediction"]["is_phishing"])
    return {
        "summary": {
            "total_scanned":  total,
            "phishing_found": phishing,
            "legitimate":     total - phishing,
        },
        "emails": results,
    }


# ─────────────────────────────────────────────────────────────
# AUTO SCAN LOOP
# Only processes emails that arrived AFTER the backend started.
# ─────────────────────────────────────────────────────────────

def auto_scan_loop():
    if not IMAP_USERNAME or not IMAP_PASSWORD:
        print("[AUTO SCAN] No IMAP credentials in .env — auto scan disabled.")
        return

    while True:
        print("\n[AUTO SCAN] Checking for new emails...")
        mail = None
        try:
            mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=15)
            mail.login(IMAP_USERNAME, IMAP_PASSWORD)
            mail.select("INBOX")

            _, message_data = mail.uid("search", None, "UNSEEN")
            uids = message_data[0].split()

            for uid in uids:
                uid_str = uid.decode()

                if is_email_scanned(uid_str):
                    continue

                _, msg_data = mail.uid("fetch", uid, "(BODY.PEEK[])")
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Gate: skip emails older than backend start time
                date_header = msg.get("Date")
                if not date_header:
                    print("[AUTO SCAN] Email has no Date header, skipping.")
                    save_scanned_email(uid_str)
                    continue

                try:
                    email_dt = _to_utc_aware(parsedate_to_datetime(date_header))
                    if email_dt < APP_START_TIME:
                        save_scanned_email(uid_str)
                        continue
                except Exception as err:
                    print(f"[AUTO SCAN] Could not parse date, skipping: {err}")
                    save_scanned_email(uid_str)
                    continue

                subject      = decode_subject(msg.get("Subject"))
                sender_raw   = msg.get("From", "")
                display_name, sender = parse_sender(sender_raw)
                body         = extract_body(msg)
                topic        = classify_topic(body)
                prediction   = predict(f"{subject} {body}")
                intel        = _gather_intelligence(msg, body)
                prediction["raw_phishing_score"] = prediction["phishing_score"]
                prediction["raw_safe_score"]     = prediction["safe_score"]
                prediction["raw_label"]          = prediction["label"]
                prediction["raw_is_phishing"]    = prediction["is_phishing"]
                prediction["raw_confidence"]     = prediction["confidence"]
                prediction   = adjust_for_reputation(
                    prediction,
                    intel["sender_email"],
                    intel.get("sender_domain_result"),
                    intel.get("sender_ip_result"),
                    intel.get("dkim_domain"),
                    intel.get("return_path_domain"),
                    display_name=display_name,
                    subject=subject,
                )

                entry = {
                    "subject":      subject or None,
                    "sender":       sender or None,
                    "display_name": display_name or None,
                    "topic":        topic,
                    "prediction":   prediction,
                    "timestamp":    datetime.now().isoformat(),
                    **intel,
                }

                with _results_lock:
                    _auto_scan_results.append(entry)

                save_scanned_email(uid_str)
                mail.uid("store", uid, "+FLAGS", "\\Seen")

                verdict = "PHISHING" if prediction["is_phishing"] else "SAFE"
                print(f"[AUTO SCAN] {verdict} — {subject} (score: {prediction['phishing_score']}%)")

        except Exception as e:
            print(f"[AUTO SCAN ERROR] {e}")
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        time.sleep(60)
