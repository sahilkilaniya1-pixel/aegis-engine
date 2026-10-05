import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Scan

stream_router = APIRouter(tags=["Real-time Dashboard"])

@stream_router.get("/scans/stream/{scan_id}")
async def stream_scan_progress(scan_id: int, db: Session = Depends(get_db)):
    """
    Server-Sent Events (SSE) endpoint to stream real-time scan status and logs 
    directly to the frontend dashboard.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        while True:
            # Refresh session to get latest status from DB (updated by Celery worker)
            db.expire_all()
            current_scan = db.query(Scan).filter(Scan.id == scan_id).first()
            
            if not current_scan:
                yield f"data: {json.dumps({'error': 'Scan removed'})}\n\n"
                break

            data = {
                "scan_id": current_scan.id,
                "scan_type": current_scan.scan_type,
                "status": current_scan.status,
                "results": current_scan.results
            }

            yield f"data: {json.dumps(data)}\n\n"

            # Stop streaming if scan is completed or failed
            if current_scan.status in ["completed", "failed"]:
                break

            await asyncio.sleep(2)  # Check every 2 seconds

    return StreamingResponse(event_generator(), media_type="text/event-stream")