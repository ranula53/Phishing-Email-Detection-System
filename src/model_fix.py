# ─────────────────────────────────────────────────────────────
# model_fix.py
# Post-processes BERT phishing scores using sender reputation
# signals (VirusTotal domain/IP) and a two-tier domain system.
#
# Tier 1 — official service domains (google.com, github.com …)
#   DKIM or Return-Path must match the sender base domain before
#   high-trust score reductions apply.  Without verification,
#   treated as Tier 2.
#
# Tier 2 — consumer email providers (gmail.com, yahoo.com …)
#   Score can be reduced but verdict never flips to Legitimate
#   because anyone can send from these addresses.
#
# Brand impersonation check — runs regardless of model verdict.
#   If a Tier 2 / unknown sender impersonates a known brand via
#   display name, local-part, or subject line, the phishing score
#   is bumped up even when the model said Legitimate.
# ─────────────────────────────────────────────────────────────

# Official service domains — companies that send from their own infrastructure
_TIER1_BASE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "github.com", "linkedin.com", "youtube.com",
    "instagram.com", "netflix.com", "dropbox.com", "zoom.us",
    "slack.com", "twitter.com", "x.com", "meta.com", "facebook.com",
    "adobe.com", "salesforce.com", "shopify.com", "stripe.com",
}

# Consumer email providers — any user can send from these
_TIER2_BASE_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "protonmail.com", "icloud.com", "aol.com",
}

# Brand keywords to detect in display name, sender local-part, or subject
_IMPERSONATION_BRANDS = {
    "google", "gmail", "youtube", "android",
    "microsoft", "outlook", "office", "onedrive", "azure", "windows",
    "apple", "icloud", "itunes",
    "amazon", "prime", "aws",
    "paypal", "github", "linkedin",
    "facebook", "instagram", "whatsapp", "meta",
    "netflix", "dropbox", "twitter",
}

# Suspicious local-parts that imply an official account
_SUSPICIOUS_LOCAL_PARTS = {
    "no-reply", "noreply", "donotreply", "do-not-reply",
    "support", "security", "admin", "account", "accounts",
    "notification", "alert", "alerts", "verify", "verification",
    "service", "helpdesk", "info", "contact", "mailer",
}

# Action words that, combined with a brand keyword in the subject, raise suspicion
_SUBJECT_ACTION_WORDS = {
    "welcome", "verify", "confirm", "reset", "suspended", "locked",
    "login", "signin", "sign-in", "access", "security", "alert",
    "warning", "update", "unusual", "unauthorized", "activate",
    "invited", "invitation", "subscription", "password",
}


def _get_base_domain(domain: str) -> str:
    """Return last two dot-separated parts (accounts.google.com → google.com)."""
    parts = domain.lower().strip().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower().strip()


def _get_domain_tier(base_domain: str) -> int:
    """1 = official service, 2 = consumer provider, 0 = unknown."""
    if base_domain in _TIER1_BASE_DOMAINS:
        return 1
    if base_domain in _TIER2_BASE_DOMAINS:
        return 2
    return 0


def _dkim_verified(dkim_domain: str | None, base_domain: str) -> bool:
    if not dkim_domain:
        return False
    return _get_base_domain(dkim_domain) == base_domain


def _return_path_verified(return_path_domain: str | None, base_domain: str) -> bool:
    if not return_path_domain:
        return False
    return _get_base_domain(return_path_domain) == base_domain


def _detect_impersonation(
    display_name: str | None,
    sender_email: str | None,
    tier: int,
    subject: str | None,
) -> str | None:
    """
    Detect brand impersonation for Tier 2 / unknown senders.
    Returns 'high', 'medium', or None.

    'high'   — display name directly uses a brand keyword
    'medium' — sender local-part uses a brand/official-sounding pattern,
               OR subject contains a brand keyword paired with an action word
    """
    if tier == 1:
        return None  # official domain — DKIM verification handles trust

    # Check 1 (HIGH): display name impersonates a brand
    if display_name:
        name_lower = display_name.lower()
        if any(brand in name_lower for brand in _IMPERSONATION_BRANDS):
            return "high"

    # Check 2 (MEDIUM): sender local-part looks like an official account
    if sender_email and "@" in sender_email:
        local = sender_email.split("@")[0].lower()
        # brand keyword in local-part  (e.g. googlesupport@gmail.com)
        if any(brand in local for brand in _IMPERSONATION_BRANDS):
            return "medium"
        # suspicious pattern (e.g. no-reply@gmail.com, support@yahoo.com)
        local_clean = local.replace("-", "").replace("_", "").replace(".", "")
        if any(p.replace("-", "") in local_clean for p in _SUSPICIOUS_LOCAL_PARTS):
            return "medium"

    # Check 3 (MEDIUM): subject has brand keyword + action word
    if subject:
        subj_lower = subject.lower()
        has_brand  = any(brand in subj_lower for brand in _IMPERSONATION_BRANDS)
        has_action = any(word in subj_lower for word in _SUBJECT_ACTION_WORDS)
        if has_brand and has_action:
            return "medium"

    return None


def _harmless_multiplier(harmless: int) -> float:
    if harmless >= 60:
        return 0.60
    elif harmless >= 41:
        return 0.75
    elif harmless >= 21:
        return 0.90
    else:
        return 1.0


def _vt_is_clean(result: dict | None) -> bool:
    if not result:
        return False
    return (
        result.get("malicious", 1) == 0
        and result.get("suspicious", 1) == 0
        and result.get("harmless", 0) >= 5
    )


def adjust_for_reputation(
    prediction: dict,
    sender_email: str | None,
    domain_result: dict | None,
    ip_result: dict | None,
    dkim_domain: str | None = None,
    return_path_domain: str | None = None,
    display_name: str | None = None,
    subject: str | None = None,
) -> dict:
    """
    Adjust phishing score using VT reputation, two-tier domain trust,
    and brand impersonation detection.

    Brand impersonation check runs BEFORE the model's early-exit so it
    can catch cases where the model said Legitimate but the sender is
    clearly impersonating a known brand from a consumer email account.

    Verdict can flip to Legitimate ONLY when:
      - Sender is Tier 1 (official service domain)
      - DKIM or Return-Path verifies the sender base domain
      - IP check is also clean

    All other cases: score may reduce but stays ≥ 51 % (Phishing).
    """
    # ── Determine sender tier ─────────────────────────────────
    tier = 0
    trusted = False
    if sender_email and "@" in sender_email:
        sender_base = _get_base_domain(sender_email.split("@")[-1])
        tier = _get_domain_tier(sender_base)
        if tier == 1:
            dkim_ok = _dkim_verified(dkim_domain, sender_base)
            rp_ok   = _return_path_verified(return_path_domain, sender_base)
            trusted = dkim_ok or rp_ok

    # ── Brand impersonation check (runs even when model says Legitimate) ──
    # If impersonation is detected, return immediately — VT clean scores for
    # consumer domains (gmail.com etc.) should not reduce this signal.
    impersonation = _detect_impersonation(display_name, sender_email, tier, subject)
    if impersonation:
        bump = 75.0 if impersonation == "high" else 55.0
        new_score = max(prediction["phishing_score"], bump)
        return {
            **prediction,
            "phishing_score":         new_score,
            "safe_score":             round(100 - new_score, 2),
            "is_phishing":            True,
            "label":                  "Phishing",
            "confidence":             round(new_score, 2),
            "impersonation_detected": impersonation,
        }

    # ── Early exit when model says Legitimate and no impersonation ───────
    if not prediction.get("is_phishing"):
        return prediction

    # ── VT reputation adjustment ──────────────────────────────
    domain_clean = _vt_is_clean(domain_result)
    ip_clean     = _vt_is_clean(ip_result)

    if not (domain_clean or ip_clean):
        return prediction  # no positive VT signal — verdict stands

    ip_mult     = _harmless_multiplier((ip_result or {}).get("harmless", 0)) if ip_clean else 1.0
    domain_mult = _harmless_multiplier((domain_result or {}).get("harmless", 0)) if domain_clean else 1.0

    # Trusted cases: DKIM verification is already the strong signal —
    # no harmless multiplier so the score stays near 50% rather than
    # dropping to near 0%.
    # Non-trusted cases: floor enforced at 51% anyway so harmless mult
    # only has a small visible effect there.
    if trusted and ip_clean and domain_clean:
        base_factor   = 0.38          # 97% → ~37%  (Legitimate, moderate confidence)
        harmless_mult = 1.0
    elif trusted and ip_clean:
        base_factor   = 0.44          # 97% → ~43%  (Legitimate, low confidence)
        harmless_mult = 1.0
    elif trusted and domain_clean:
        base_factor   = 0.55          # domain alone is spoofable — stays Phishing
        harmless_mult = 1.0
    elif ip_clean and domain_clean:
        base_factor   = 0.65          # unknown sender — stays Phishing
        harmless_mult = min(ip_mult, domain_mult)
    elif ip_clean:
        base_factor   = 0.75
        harmless_mult = ip_mult
    else:                              # domain_clean only
        base_factor   = 0.85
        harmless_mult = domain_mult

    new_score = round(prediction["phishing_score"] * base_factor * harmless_mult, 2)

    # Tier 2, Tier 1 unverified, unknown: never flip verdict to Legitimate
    can_flip = trusted and ip_clean
    if not can_flip:
        new_score = max(new_score, 51.0)

    is_phishing = new_score >= 50

    return {
        **prediction,
        "phishing_score": new_score,
        "safe_score":     round(100 - new_score, 2),
        "is_phishing":    is_phishing,
        "label":          "Phishing" if is_phishing else "Legitimate",
        "confidence":     round((100 - new_score) if not is_phishing else new_score, 2),
    }
