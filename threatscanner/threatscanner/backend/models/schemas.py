"""
Pydantic models for request validation and response serialisation.
All user input passes through these before reaching any business logic.
"""
from pydantic import BaseModel, HttpUrl, field_validator
from typing import List, Optional
import bleach


# ── Requests ─────────────────────────────────────────────────────────────────

class TextScanRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def sanitise(cls, v: str) -> str:
        # Strip HTML tags / JS to prevent XSS in responses
        cleaned = bleach.clean(v, tags=[], strip=True)
        if len(cleaned) > 50_000:
            raise ValueError("Text exceeds 50,000 character limit")
        if not cleaned.strip():
            raise ValueError("Text must not be empty")
        return cleaned


class URLScanRequest(BaseModel):
    url: str  # kept as str; SSRF guard does deep validation

    @field_validator("url")
    @classmethod
    def basic_check(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length")
        return v


# ── Response fragments ────────────────────────────────────────────────────────

class Signal(BaseModel):
    label: str
    category: str        # "phishing" | "spam" | "malware" | "suspicious" | "safe"
    weight: float        # 0.0 – 1.0


class ScanResponse(BaseModel):
    score: int           # 0 – 100
    level: str           # "safe" | "suspicious" | "dangerous"
    summary: str
    signals: List[Signal]
    extracted_text: Optional[str] = None   # image scans only
    scan_type: str       # "text" | "image" | "url"
