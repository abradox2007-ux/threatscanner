"""
NLP Engine — analyses plain text for spam, phishing, and malicious language.
Uses a layered heuristic approach that works without any API keys.
Optionally upgrades to a transformer model if transformers is installed.
"""
import re
from typing import List
from services.risk_scorer import ScanSignal

# ── Keyword / pattern dictionaries ───────────────────────────────────────────

URGENCY_PHRASES = [
    r"\burgent\b", r"\bact now\b", r"\bimmediate(ly)?\b", r"\bexpires?\b",
    r"\blimited time\b", r"\btoday only\b", r"\bdon't (wait|delay|miss)\b",
    r"\blast chance\b", r"\bresponse required\b", r"\bdeadline\b",
]

PHISHING_PHRASES = [
    r"\bverify your (account|identity|email|password)\b",
    r"\bconfirm your (details|information|credentials)\b",
    r"\byour account (has been|will be) (suspended|locked|closed|terminated)\b",
    r"\bclick (here|the link|below) to (verify|confirm|update|restore)\b",
    r"\bunusual (activity|sign.?in|login|access)\b",
    r"\bsecurity alert\b", r"\bpassword (reset|expired|expiring)\b",
    r"\bbank (account|details|transfer)\b",
    r"\bprovide (your )?(credit card|ssn|social security|date of birth)\b",
]

FINANCIAL_SCAM_PHRASES = [
    r"\byou (have|'ve) won\b", r"\bcongratulations.{0,30}(won|winner|selected|chosen)\b",
    r"\bfree (gift|prize|iphone|ipad|voucher|reward)\b",
    r"\bclaim (your|the) (prize|reward|gift)\b",
    r"\b\$\d{3,}[\s,]*\d*\s*(per day|a day|daily|weekly|per week)\b",
    r"\bmake money (fast|online|from home|easily)\b",
    r"\bwork from home.{0,30}earn\b",
    r"\bnigerian\b.{0,40}\b(million|funds|transfer)\b",
    r"\binheritance.{0,40}(million|funds|transfer)\b",
]

SUSPICIOUS_LINKS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # bare IP link
    r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd",    # URL shorteners
    r"https?://[^\s]{60,}",                              # very long URLs
]

SENSITIVE_DATA_REQUESTS = [
    r"\b(enter|provide|send|reply with).{0,30}(password|pin|otp|code)\b",
    r"\bcredit card (number|details|info)\b",
    r"\bsocial security\b", r"\bssn\b",
    r"\bdate of birth\b", r"\bdob\b",
    r"\bmother'?s maiden name\b",
]

ALL_CAPS_THRESHOLD = 0.35   # flag if >35% of alpha chars are uppercase
EXCLAMATION_THRESHOLD = 3   # flag if 3+ exclamation marks in body


def analyse_text(text: str) -> List[ScanSignal]:
    signals: List[ScanSignal] = []
    lower = text.lower()

    # --- Urgency language
    matched_urgency = [p for p in URGENCY_PHRASES if re.search(p, lower)]
    if len(matched_urgency) >= 2:
        signals.append(ScanSignal(
            label=f"Urgency language detected ({len(matched_urgency)} phrases)",
            weight=0.20, category="spam"
        ))
    elif len(matched_urgency) == 1:
        signals.append(ScanSignal(
            label="Urgency language detected",
            weight=0.10, category="spam"
        ))

    # --- Phishing indicators
    matched_phish = [p for p in PHISHING_PHRASES if re.search(p, lower)]
    if matched_phish:
        signals.append(ScanSignal(
            label=f"Phishing language: \"{_first_match(matched_phish[0], lower)}\"",
            weight=min(0.25 * len(matched_phish), 0.65),
            category="phishing"
        ))

    # --- Financial / reward scams
    matched_fin = [p for p in FINANCIAL_SCAM_PHRASES if re.search(p, lower)]
    if matched_fin:
        signals.append(ScanSignal(
            label=f"Financial scam language detected",
            weight=min(0.25 * len(matched_fin), 0.55),
            category="phishing"
        ))

    # --- Sensitive data requests
    matched_sens = [p for p in SENSITIVE_DATA_REQUESTS if re.search(p, lower)]
    if matched_sens:
        signals.append(ScanSignal(
            label="Request for sensitive personal data (password / SSN / card number)",
            weight=0.50, category="phishing"
        ))

    # --- Suspicious inline links
    matched_links = [p for p in SUSPICIOUS_LINKS if re.search(p, lower)]
    if matched_links:
        signals.append(ScanSignal(
            label="Suspicious link found (bare IP or URL shortener)",
            weight=0.30, category="suspicious"
        ))

    # --- Excessive ALL-CAPS
    alpha_chars = [c for c in text if c.isalpha()]
    if alpha_chars:
        upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if upper_ratio > ALL_CAPS_THRESHOLD and len(alpha_chars) > 30:
            signals.append(ScanSignal(
                label=f"Excessive capitalisation ({int(upper_ratio*100)}% uppercase)",
                weight=0.10, category="spam"
            ))

    # --- Exclamation marks
    excl_count = text.count("!")
    if excl_count >= EXCLAMATION_THRESHOLD:
        signals.append(ScanSignal(
            label=f"Excessive exclamation marks ({excl_count})",
            weight=0.08, category="spam"
        ))

    # --- Mismatched sender domain (email-specific heuristic)
    from_match = re.search(r"from:\s*\S+@(\S+)", lower)
    reply_match = re.search(r"reply-to:\s*\S+@(\S+)", lower)
    if from_match and reply_match and from_match.group(1) != reply_match.group(1):
        signals.append(ScanSignal(
            label="From and Reply-To domains don't match — common spoofing indicator",
            weight=0.40, category="phishing"
        ))

    # --- Attachment lure phrases
    if re.search(r"(open|see|view|check).{0,20}(attachment|attached|document|file)", lower):
        signals.append(ScanSignal(
            label="Attachment lure language detected",
            weight=0.20, category="suspicious"
        ))

    return signals


def _first_match(pattern: str, text: str) -> str:
    """Return the matched substring for display."""
    m = re.search(pattern, text)
    return m.group(0) if m else pattern
