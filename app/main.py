from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import engine, Base, get_db
from app.models import Target, Scan, Vulnerability
from app.tasks.recon import run_subdomain_recon
from app.tasks.port_scan import run_port_scan
from pydantic import BaseModel

# Database tables auto-create
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Aegis Engine API", version="1.0.0")

class TargetCreate(BaseModel):
    domain: str

@app.get("/")
def read_root():
    return {"platform": "Aegis Engine", "status": "Online", "phase": "1 & 2 Active"}

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