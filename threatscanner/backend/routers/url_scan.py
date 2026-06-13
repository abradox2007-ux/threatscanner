from fastapi import APIRouter, HTTPException
from models.schemas import URLScanRequest, ScanResponse, Signal
from services.ssrf_guard import validate_url_safe
from services.url_engine import analyse_url
from services.risk_scorer import compute_score

router = APIRouter()


@router.post("/url", response_model=ScanResponse)
async def scan_url(req: URLScanRequest):
    # SSRF guard — always runs first, before any analysis
    try:
        safe_url = validate_url_safe(req.url)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, detail=str(e))

    signals = await analyse_url(safe_url)
    result  = compute_score(signals)

    return ScanResponse(
        score=result.score,
        level=result.level,
        summary=result.summary,
        signals=[Signal(label=s.label, category=s.category, weight=s.weight)
                 for s in result.signals],
        scan_type="url",
    )
