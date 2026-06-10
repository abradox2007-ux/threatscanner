from fastapi import APIRouter
from models.schemas import TextScanRequest, ScanResponse, Signal
from services.nlp_engine import analyse_text
from services.risk_scorer import compute_score

router = APIRouter()


@router.post("/text", response_model=ScanResponse)
async def scan_text(req: TextScanRequest):
    signals = analyse_text(req.text)
    result  = compute_score(signals)
    return ScanResponse(
        score=result.score,
        level=result.level,
        summary=result.summary,
        signals=[Signal(label=s.label, category=s.category, weight=s.weight)
                 for s in result.signals],
        scan_type="text",
    )
