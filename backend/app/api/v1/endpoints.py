from fastapi import APIRouter, HTTPException
from ...models.schemas import URLScanRequest, URLScanResponse
from ...analyzers.url_analyzer import analyze_url
from ...services.risk_engine import calculate_url_risk

router = APIRouter()

@router.post("/scan/url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    try:
        evidence = await analyze_url(request.url)
        risk_assessment = calculate_url_risk(evidence)
        return URLScanResponse(
            url=request.url,
            evidence=evidence,
            risk_assessment=risk_assessment
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error during URL analysis: {str(e)}")
