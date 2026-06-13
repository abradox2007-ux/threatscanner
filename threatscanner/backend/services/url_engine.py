"""
URL Engine — checks URLs against multiple threat intelligence sources.
Works with zero API keys (heuristics only), and improves with keys set.
"""
import ssl
import socket
import re
import asyncio
from urllib.parse import urlparse
from typing import List
from datetime import datetime, timezone
import httpx

from config import SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY
from services.risk_scorer import ScanSignal

# ── Known bad TLDs / patterns ─────────────────────────────────────────────────
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan"}
IP_IN_URL = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HOMOGLYPH  = re.compile(r"[а-яёА-ЯЁ]")   # Cyrillic chars in a Latin hostname


async def analyse_url(url: str) -> List[ScanSignal]:
    signals: List[ScanSignal] = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # ── Heuristics (no API key needed) ───────────────────────────────────────

    if IP_IN_URL.match(hostname):
        signals.append(ScanSignal(
            label="URL uses a raw IP address instead of a domain name",
            weight=0.40, category="suspicious"
        ))

    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(ScanSignal(
            label=f"High-risk top-level domain: {tld}",
            weight=0.25, category="suspicious"
        ))

    if HOMOGLYPH.search(hostname):
        signals.append(ScanSignal(
            label="Hostname contains Cyrillic characters — possible homoglyph attack",
            weight=0.55, category="phishing"
        ))

    if len(hostname) > 50:
        signals.append(ScanSignal(
            label=f"Unusually long hostname ({len(hostname)} chars)",
            weight=0.15, category="suspicious"
        ))

    subdomain_count = hostname.count(".") - 1
    if subdomain_count >= 3:
        signals.append(ScanSignal(
            label=f"Excessive subdomains ({subdomain_count}) — common in phishing URLs",
            weight=0.20, category="phishing"
        ))

    if parsed.scheme == "http":
        signals.append(ScanSignal(
            label="Connection is unencrypted (HTTP, not HTTPS)",
            weight=0.15, category="suspicious"
        ))

    # Shortened URLs
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rebrand.ly"}
    if hostname in SHORTENERS:
        signals.append(ScanSignal(
            label="URL is a shortener link — destination is hidden",
            weight=0.20, category="suspicious"
        ))

    # ── SSL check ─────────────────────────────────────────────────────────────
    ssl_ok = await _check_ssl(hostname)
    if not ssl_ok and parsed.scheme == "https":
        signals.append(ScanSignal(
            label="SSL certificate is invalid, expired, or self-signed",
            weight=0.35, category="suspicious"
        ))

    # ── Domain age (whois) ────────────────────────────────────────────────────
    age_days = await _get_domain_age(hostname)
    if age_days is not None:
        if age_days < 7:
            signals.append(ScanSignal(
                label=f"Domain registered {age_days} day(s) ago — extremely new",
                weight=0.50, category="phishing"
            ))
        elif age_days < 30:
            signals.append(ScanSignal(
                label=f"Domain registered {age_days} day(s) ago — newly created",
                weight=0.30, category="suspicious"
            ))

    # ── Google Safe Browsing ──────────────────────────────────────────────────
    if SAFE_BROWSING_API_KEY:
        gsb = await _check_safe_browsing(url)
        if gsb:
            signals.append(ScanSignal(
                label=f"Google Safe Browsing: {gsb}",
                weight=0.90, category="malware"
            ))

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if VIRUSTOTAL_API_KEY:
        vt = await _check_virustotal(url)
        if vt:
            signals.append(ScanSignal(
                label=f"VirusTotal: flagged by {vt} engine(s)",
                weight=min(0.15 * vt, 0.90), category="malware"
            ))

    return signals


async def _check_ssl(hostname: str) -> bool:
    def _check():
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(4)
                s.connect((hostname, 443))
            return True
        except Exception:
            return False
    return await asyncio.get_event_loop().run_in_executor(None, _check)


async def _get_domain_age(hostname: str) -> int | None:
    def _whois():
        try:
            import whois
            w = whois.whois(hostname)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - created).days
        except Exception:
            pass
        return None
    return await asyncio.get_event_loop().run_in_executor(None, _whois)


async def _check_safe_browsing(url: str) -> str:
    """Returns threat type string or empty string if clean."""
    payload = {
        "client": {"clientId": "threatscanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            data = r.json()
            if data.get("matches"):
                t = data["matches"][0].get("threatType", "THREAT")
                return t.replace("_", " ").title()
    except Exception:
        pass
    return ""


async def _check_virustotal(url: str) -> int:
    """Returns number of engines that flagged the URL, or 0 if clean."""
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except Exception:
        pass
    return 0
