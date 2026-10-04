from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import engine, Base, get_db
from app.models import Target, Scan, Vulnerability
from app.tasks.recon import run_subdomain_recon
from app.tasks.port_scan import run_port_scan
from app.tasks.ai_triage import run_ai_triage
from app.tasks.fuzzing import run_directory_fuzzing
from app.tasks.active_scanner import run_active_vulnerability_scan
from pydantic import BaseModel
from services.api import reports

# Database tables auto-create
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Aegis Engine API", version="1.0.0")

# Register Phase 6 Reporting Router
app.include_router(reports.router, prefix="/api/v1", tags=["Reports"])

class TargetCreate(BaseModel):
    domain: str

@app.get("/")
def read_root():
    return {"platform": "Aegis Engine", "status": "Online", "phase": "1, 2, 3, 4, 5 & 6 Active"}

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