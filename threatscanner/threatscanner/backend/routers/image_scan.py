from fastapi import APIRouter, UploadFile, File, HTTPException
from models.schemas import ScanResponse, Signal
from services.ocr_engine import extract_text_from_image
from services.nlp_engine import analyse_text
from services.risk_scorer import compute_score
from config import MAX_UPLOAD_BYTES

router = APIRouter()

ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/bmp"}


@router.post("/image", response_model=ScanResponse)
async def scan_image(file: UploadFile = File(...)):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, detail=f"Unsupported file type: {file.content_type}")

    image_bytes = await file.read()
    if len(image_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, detail="File exceeds 10 MB upload limit")

    # OCR + metadata signals
    extracted_text, meta_signals = extract_text_from_image(image_bytes)

    # NLP on OCR'd text
    text_signals = analyse_text(extracted_text) if extracted_text.strip() else []

    all_signals = meta_signals + text_signals
    result = compute_score(all_signals, extracted_text=extracted_text)

    return ScanResponse(
        score=result.score,
        level=result.level,
        summary=result.summary,
        signals=[Signal(label=s.label, category=s.category, weight=s.weight)
                 for s in result.signals],
        extracted_text=result.extracted_text[:2000] if result.extracted_text else None,
        scan_type="image",
    )
