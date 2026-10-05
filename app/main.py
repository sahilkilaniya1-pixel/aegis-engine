from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import tempfile

from app.database import engine, Base, get_db, SessionLocal
from app.models import Target, Scan, Vulnerability
from app.reporter import AdvancedComplianceReporter

# Background Celery Tasks
from app.tasks.recon import run_subdomain_recon
from app.tasks.port_scan import run_port_scan
from app.tasks.ai_triage import run_ai_triage
from app.tasks.fuzzing import run_directory_fuzzing
from app.tasks.active_scanner import run_active_vulnerability_scan
from app.tasks.payload_scanner import run_payload_scan
from app.tasks.crawler import run_crawler_scan

from pydantic import BaseModel

# Core Routers, Auth Router & Stream Router
from app.proxy import proxy_router
from app.oob_server import oob_router
from app.auth_macro import macro_router
from app.routers.auth_router import auth_router
from app.routers.stream_router import stream_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Database tables auto-create
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown logic

app = FastAPI(
    title="AegisEngine Enterprise VAPT Platform",
    version="1.0.0",
    description="Enterprise-grade Vulnerability Assessment and Penetration Testing Platform with Burp Suite Pro parity.",
    lifespan=lifespan
)

# Register Routers
app.include_router(proxy_router)
app.include_router(oob_router)
app.include_router(macro_router)
app.include_router(auth_router)
app.include_router(stream_router)

class TargetCreate(BaseModel):
    domain: str

@app.get("/")
def read_root():
    return {
        "platform": "AegisEngine",
        "status": "Online",
        "modules": [
            "Proxy Engine",
            "OOB Collaborator",
            "Auth & Macro Engine",
            "Recon & Port Scanner",
            "Active Vulnerability Scanner",
            "Payload & Crawler Engine",
            "AI Triage & Advanced PDF/HTML Compliance Reports",
            "JWT RBAC Authentication & Nuclei YAML Engine",
            "Real-time SSE Dashboard Stream"
        ]
    }

@app.post("/targets/")
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    existing = db.query(Target).filter(Target.domain == payload.domain).first()
    if existing:
        return {"message": "Target already exists", "target_id": existing.id}
    
    target = Target(domain=payload.domain)
    db.add(target)
    db.commit()
    db.refresh(target)
    return {"message": "Target added successfully", "target_id": target.id, "domain": target.domain}

@app.post("/scans/recon/{target_id}")
def trigger_recon(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(target_id=target.id, scan_type="recon", status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    task = run_subdomain_recon.delay(scan.id, target.domain)
    
    return {
        "message": "Recon scan queued successfully",
        "scan_id": scan.id,
        "task_id": task.id,
        "domain": target.domain
    }

@app.post("/scans/port-scan/{target_id}")
def trigger_port_scan(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(target_id=target.id, scan_type="port_scan", status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    task = run_port_scan.delay(scan.id, target.domain)
    
    return {
        "message": "Port scan queued successfully",
        "scan_id": scan.id,
        "task_id": task.id,
        "domain": target.domain
    }

@app.post("/scans/ai-triage/{target_id}/{scan_id}")
def trigger_ai_triage(target_id: int, scan_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not target or not scan:
        raise HTTPException(status_code=404, detail="Target or Scan not found")
    
    triage_scan = Scan(target_id=target.id, scan_type="ai_triage", status="pending")
    db.add(triage_scan)
    db.commit()
    db.refresh(triage_scan)
    
    task = run_ai_triage.delay(triage_scan.id, target.id)
    
    return {
        "message": "AI Triage scan queued successfully",
        "scan_id": triage_scan.id,
        "task_id": task.id
    }

@app.post("/scans/fuzzing/{target_id}")
def trigger_directory_fuzzing(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(target_id=target.id, scan_type="fuzzing", status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    task = run_directory_fuzzing.delay(scan.id, target.domain)
    
    return {
        "message": "Directory fuzzing scan queued successfully",
        "scan_id": scan.id,
        "task_id": task.id,
        "domain": target.domain
    }

@app.post("/scans/active-scan/{target_id}")
def trigger_active_scan(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(target_id=target.id, scan_type="active_scan", status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    task = run_active_vulnerability_scan.delay(scan.id, target.id, target.domain)
    
    return {
        "message": "Active vulnerability scan queued successfully",
        "scan_id": scan.id,
        "task_id": task.id,
        "domain": target.domain
    }

@app.post("/scans/payload-scan/{target_id}")
def trigger_payload_scan(target_id: int, target_url: str, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(target_id=target.id, scan_type="payload_scan", status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    task = run_payload_scan.delay(scan.id, target.id, target_url)
    
    return {
        "message": "Payload security scan queued successfully",
        "scan_id": scan.id,
        "task_id": task.id,
        "target_url": target_url
    }

@app.post("/scans/crawl/{target_id}")
def trigger_crawl_scan(target_id: int, target_url: str):
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        new_scan = Scan(target_id=target_id, scan_type="crawler", status="pending")
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        
        task = run_crawler_scan.delay(new_scan.id, target_id, target_url)
        
        return {
            "message": "Web crawler scan initiated successfully",
            "scan_id": new_scan.id,
            "celery_task_id": task.id,
            "target_url": target_url
        }
    finally:
        db.close()

@app.get("/scans/{scan_id}")
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "results": scan.results,
        "created_at": scan.created_at
    }

# Advanced Compliance Reporting Endpoints (HTML & PDF)
@app.get("/reports/{target_id}", response_class=HTMLResponse, tags=["Reports"])
def get_security_report_html(target_id: int, db: Session = Depends(get_db)):
    reporter = AdvancedComplianceReporter(db)
    return reporter.generate_html_report(target_id)

@app.get("/reports/{target_id}/pdf", tags=["Reports"])
def get_security_report_pdf(target_id: int, db: Session = Depends(get_db)):
    reporter = AdvancedComplianceReporter(db)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    temp_file.close()
    
    reporter.generate_pdf_report(target_id, temp_file.name)
    return FileResponse(temp_file.name, media_type="application/pdf", filename=f"AegisEngine_Security_Report_{target_id}.pdf")