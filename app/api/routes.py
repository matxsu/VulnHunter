import asyncio
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import PlainTextResponse, Response

from app.models.scan import ScanRequest, ScanResult, ScanStatus
from app.scanner.engine import run_scan, get_scan, list_scans, _scan_store
from app.reporter.report import generate_markdown, generate_pdf

router = APIRouter(prefix="/api/v1")


@router.post("/scans", response_model=ScanResult, status_code=202)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new vulnerability scan."""
    scan_id = str(uuid.uuid4())

    # Validate target URL
    if not request.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Target URL must start with http:// or https://")

    result = ScanResult(
        scan_id=scan_id,
        target_url=request.target_url,
        status=ScanStatus.PENDING,
    )
    _scan_store[scan_id] = result

    background_tasks.add_task(run_scan, scan_id, request)
    return result


@router.get("/scans", response_model=list[ScanResult])
async def get_all_scans():
    """List all scans."""
    return list_scans()


@router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan_status(scan_id: str):
    """Get scan status and results."""
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return result


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str):
    """Delete a scan result."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    del _scan_store[scan_id]


@router.get("/scans/{scan_id}/report/markdown", response_class=PlainTextResponse)
async def get_markdown_report(scan_id: str):
    """Download Markdown report."""
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    if result.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        raise HTTPException(status_code=409, detail="Scan not yet completed")

    md = generate_markdown(result)
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="vulnhunter-{scan_id}.md"'}
    )


@router.get("/scans/{scan_id}/report/pdf")
async def get_pdf_report(scan_id: str):
    """Download PDF report."""
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    if result.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        raise HTTPException(status_code=409, detail="Scan not yet completed")

    try:
        pdf_bytes = generate_pdf(result)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="vulnhunter-{scan_id}.pdf"'}
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "VulnHunter",
        "version": "1.0.0",
        "scans_in_memory": len(_scan_store),
    }