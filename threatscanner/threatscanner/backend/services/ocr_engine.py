"""
OCR Engine — extracts text from uploaded images and checks EXIF metadata.
Uses EasyOCR with a Pillow/Tesseract fallback.
"""
import io
import re
from typing import Tuple, List
from services.risk_scorer import ScanSignal

try:
    import easyocr
    _reader = easyocr.Reader(["en"], verbose=False)
    OCR_BACKEND = "easyocr"
except ImportError:
    _reader = None
    OCR_BACKEND = "none"

try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def extract_text_from_image(image_bytes: bytes) -> Tuple[str, List[ScanSignal]]:
    """
    Returns (extracted_text, metadata_signals).
    extracted_text is passed to the NLP engine for content analysis.
    """
    signals: List[ScanSignal] = []
    extracted = ""

    if not PIL_AVAILABLE:
        return extracted, [ScanSignal(
            label="Pillow not installed — image analysis unavailable",
            weight=0.0, category="suspicious"
        )]

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception:
        return extracted, [ScanSignal(
            label="Could not decode image file",
            weight=0.05, category="suspicious"
        )]

    # ── EXIF metadata checks ─────────────────────────────────────────────────
    exif_signals = _check_exif(img)
    signals.extend(exif_signals)

    # ── Image dimension sanity ───────────────────────────────────────────────
    w, h = img.size
    if w * h > 25_000_000:
        signals.append(ScanSignal(
            label="Unusually large image — may be used to hide content from scanners",
            weight=0.10, category="suspicious"
        ))

    # ── OCR ──────────────────────────────────────────────────────────────────
    if _reader is not None:
        try:
            results = _reader.readtext(image_bytes, detail=0, paragraph=True)
            extracted = " ".join(results).strip()
        except Exception as e:
            signals.append(ScanSignal(
                label=f"OCR extraction failed: {e}",
                weight=0.0, category="suspicious"
            ))
    else:
        # Tesseract fallback
        try:
            import pytesseract
            extracted = pytesseract.image_to_string(img).strip()
        except Exception:
            signals.append(ScanSignal(
                label="No OCR library available — install easyocr or pytesseract",
                weight=0.0, category="suspicious"
            ))

    # ── Embedded URL check ───────────────────────────────────────────────────
    urls = re.findall(r"https?://[^\s]+", extracted)
    if urls:
        signals.append(ScanSignal(
            label=f"URL(s) found in image text: {', '.join(urls[:3])}",
            weight=0.15, category="suspicious"
        ))

    return extracted, signals


def _check_exif(img) -> List[ScanSignal]:
    signals = []
    try:
        exif_data = img._getexif()
        if not exif_data:
            return signals

        tags = {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items()}

        # GPS data in a screenshot is unusual
        if "GPSInfo" in tags:
            signals.append(ScanSignal(
                label="Image contains GPS metadata — unusual for a screenshot",
                weight=0.15, category="suspicious"
            ))

        # Software tag can reveal editing tools used to craft the image
        software = tags.get("Software", "")
        EDITING_TOOLS = ["photoshop", "gimp", "illustrator", "canva", "figma"]
        if any(t in str(software).lower() for t in EDITING_TOOLS):
            signals.append(ScanSignal(
                label=f"Image was edited with {software} — possibly crafted content",
                weight=0.20, category="suspicious"
            ))

        # DateTime created vs modified mismatch
        dt_orig = tags.get("DateTimeOriginal", "")
        dt_mod  = tags.get("DateTime", "")
        if dt_orig and dt_mod and dt_orig != dt_mod:
            signals.append(ScanSignal(
                label="Image creation and modification timestamps differ",
                weight=0.10, category="suspicious"
            ))

    except Exception:
        pass  # Non-JPEG images may not have EXIF

    return signals
