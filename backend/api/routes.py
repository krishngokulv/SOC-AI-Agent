"""FastAPI route definitions for the SOC-AI-Agent API."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from database.db import get_db
from agent.orchestrator import Orchestrator
from api.websocket import investigation_manager

logger = logging.getLogger(__name__)

router = APIRouter()

# Track running investigations
_running_investigations: dict = {}


@router.post("/api/investigate")
async def investigate_alert(
    content: str = Form(...),
    alert_type: str = Form("auto"),
) -> JSONResponse:
    """Submit raw alert text for investigation.

    Args:
        content: Raw alert text content.
        alert_type: Optional type hint (auto, sysmon, firewall, phishing, etc.)

    Returns:
        JSON with alert_id for tracking the investigation.
    """
    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="Alert content cannot be empty")

    db = await get_db()
    orchestrator = Orchestrator(db)

    # Parse to get alert_id early
    alert = orchestrator.parse_alert(content.strip(), alert_type)
    alert_id = alert.alert_id

    # Run investigation in background
    async def run_investigation():
        try:
            async for event in orchestrator.investigate(content.strip(), alert_type, alert_id=alert_id):
                await investigation_manager.broadcast(alert_id, event)
        except Exception as e:
            logger.exception("Investigation %s failed", alert_id)
            await investigation_manager.broadcast(alert_id, {
                "stage": "error",
                "status": "error",
                "detail": str(e),
            })
        finally:
            await orchestrator.close()
            _running_investigations.pop(alert_id, None)

    task = asyncio.create_task(run_investigation())
    _running_investigations[alert_id] = task

    return JSONResponse(
        content={
            "alert_id": alert_id,
            "status": "investigating",
            "message": "Investigation started. Connect to WebSocket for real-time updates.",
            "ws_url": f"/ws/investigate/{alert_id}",
        },
        status_code=202,
    )


@router.post("/api/investigate/upload")
async def investigate_upload(
    file: UploadFile = File(...),
    alert_type: str = Form("auto"),
) -> JSONResponse:
    """Upload a file for investigation.

    Supports .xml, .log, .eml, .txt, and .pcap files.

    Args:
        file: The uploaded file.
        alert_type: Optional type hint.

    Returns:
        JSON with alert_id for tracking.
    """
    allowed_extensions = {".xml", ".log", ".eml", ".txt", ".pcap", ".json", ".csv"}
    file_ext = Path(file.filename or "").suffix.lower()
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_ext}. Allowed: {', '.join(allowed_extensions)}",
        )

    try:
        content = await file.read()
        text_content = content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    if not text_content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # Auto-detect type from extension if auto
    if alert_type == "auto":
        ext_type_map = {
            ".xml": "sysmon",
            ".eml": "phishing",
            ".pcap": "pcap",
        }
        alert_type = ext_type_map.get(file_ext, "auto")

    db = await get_db()
    orchestrator = Orchestrator(db)
    alert = orchestrator.parse_alert(text_content.strip(), alert_type)
    alert_id = alert.alert_id

    async def run_investigation():
        try:
            async for event in orchestrator.investigate(text_content.strip(), alert_type, alert_id=alert_id):
                await investigation_manager.broadcast(alert_id, event)
        except Exception as e:
            logger.exception("Investigation %s (upload) failed", alert_id)
            await investigation_manager.broadcast(alert_id, {
                "stage": "error",
                "status": "error",
                "detail": str(e),
            })
        finally:
            await orchestrator.close()
            _running_investigations.pop(alert_id, None)

    task = asyncio.create_task(run_investigation())
    _running_investigations[alert_id] = task

    return JSONResponse(
        content={
            "alert_id": alert_id,
            "status": "investigating",
            "filename": file.filename,
            "ws_url": f"/ws/investigate/{alert_id}",
        },
        status_code=202,
    )


@router.get("/api/investigations")
async def list_investigations(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
) -> JSONResponse:
    """List all investigations with pagination and filtering.

    Args:
        limit: Number of results per page.
        offset: Pagination offset.
        verdict: Filter by verdict type.
        alert_type: Filter by alert type.

    Returns:
        Paginated list of investigations.
    """
    db = await get_db()
    investigations, total = await db.list_investigations(
        limit=limit,
        offset=offset,
        verdict_filter=verdict,
        alert_type_filter=alert_type,
    )

    return JSONResponse(content={
        "data": [inv.to_dict() for inv in investigations],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@router.get("/api/investigations/{alert_id}")
async def get_investigation(alert_id: str) -> JSONResponse:
    """Get full investigation details by alert_id.

    Args:
        alert_id: The investigation alert ID.

    Returns:
        Complete investigation data.
    """
    db = await get_db()

    # Try by alert_id first
    investigation = await db.get_investigation(alert_id)

    # Try by database ID if not found
    if not investigation:
        try:
            db_id = int(alert_id)
            investigation = await db.get_investigation_by_db_id(db_id)
        except (ValueError, TypeError):
            pass

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Include buffered events if investigation is still running
    result = investigation.to_detail_dict()
    if alert_id in _running_investigations:
        result["status"] = "in_progress"
        result["events"] = investigation_manager.get_buffered_events(investigation.alert_id)
    else:
        result["status"] = "complete"

    return JSONResponse(content=result)


@router.get("/api/reports/{alert_id}/html")
async def get_html_report(alert_id: str) -> HTMLResponse:
    """Get the HTML report for an investigation.

    Args:
        alert_id: The investigation alert ID.

    Returns:
        HTML report content.
    """
    db = await get_db()
    investigation = await db.get_investigation(alert_id)

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if not investigation.report_path_html:
        raise HTTPException(status_code=404, detail="HTML report not generated yet")

    report_path = Path(investigation.report_path_html)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    return HTMLResponse(content=content)


@router.get("/api/reports/{alert_id}/pdf")
async def get_pdf_report(alert_id: str):
    """Download the PDF report for an investigation.

    Args:
        alert_id: The investigation alert ID.

    Returns:
        PDF file download.
    """
    db = await get_db()
    investigation = await db.get_investigation(alert_id)

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if not investigation.report_path_pdf:
        raise HTTPException(status_code=404, detail="PDF report not generated yet")

    report_path = Path(investigation.report_path_pdf)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="PDF file not found on disk")

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=f"soc_report_{alert_id[:8]}.pdf",
    )


@router.get("/api/iocs")
async def list_iocs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None),
) -> JSONResponse:
    """List all IOCs across all investigations.

    Args:
        limit: Number of results per page.
        offset: Pagination offset.
        search: Search filter for IOC values.
        ioc_type: Filter by IOC type.

    Returns:
        Paginated list of IOCs.
    """
    db = await get_db()
    iocs, total = await db.list_iocs(
        limit=limit,
        offset=offset,
        search=search,
        ioc_type=ioc_type,
    )

    return JSONResponse(content={
        "data": [ioc.to_dict() for ioc in iocs],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@router.get("/api/iocs/{ioc_value:path}")
async def get_ioc_details(ioc_value: str) -> JSONResponse:
    """Get all intelligence on a specific IOC.

    Args:
        ioc_value: The IOC value to look up.

    Returns:
        All records and enrichment data for this IOC.
    """
    db = await get_db()
    records = await db.get_ioc_details(ioc_value)

    if not records:
        raise HTTPException(status_code=404, detail="IOC not found")

    return JSONResponse(content={
        "ioc_value": ioc_value,
        "records": [r.to_dict() for r in records],
        "total_sightings": len(records),
    })


@router.get("/api/stats")
async def get_stats() -> JSONResponse:
    """Get dashboard statistics.

    Returns:
        Aggregate stats for the dashboard.
    """
    db = await get_db()
    stats = await db.get_stats()
    return JSONResponse(content=stats)


@router.get("/api/mitre/heatmap")
async def get_mitre_heatmap() -> JSONResponse:
    """Get MITRE ATT&CK heatmap data.

    Returns:
        Technique frequency data for the heatmap.
    """
    db = await get_db()
    heatmap = await db.get_mitre_heatmap()
    return JSONResponse(content=heatmap)


@router.websocket("/ws/investigate/{alert_id}")
async def websocket_investigation(websocket: WebSocket, alert_id: str):
    """WebSocket endpoint for real-time investigation streaming.

    Connects to an ongoing investigation and streams progress events.

    Args:
        websocket: The WebSocket connection.
        alert_id: The investigation alert ID.
    """
    await investigation_manager.connect(websocket, alert_id)
    try:
        while True:
            # Keep connection alive, handle client messages
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive
                try:
                    await websocket.send_json({"type": "keepalive"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        investigation_manager.disconnect(websocket, alert_id)
