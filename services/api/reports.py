from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Any
from app.database import get_db
from app.models import Target, Scan, Vulnerability

router = APIRouter()

@router.get("/report/{target_id}", response_model=Any)
def generate_consolidated_report(target_id: int, db: Session = Depends(get_db)):
    # 1. Target check karein
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # 2. Scans fetch karein
    scans = db.query(Scan).filter(Scan.target_id == target_id).all()
    
    # 3. Vulnerabilities fetch karein
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.target_id == target_id).all()
    
    vuln_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }
    
    vuln_list = []
    for v in vulnerabilities:
        sev = v.severity.capitalize() if v.severity else "Info"
        if sev in vuln_summary:
            vuln_summary[sev] += 1
        
        vuln_list.append({
            "id": v.id,
            "title": v.title,
            "severity": sev,
            "description": v.description,
            "matched_at": v.matched_at
        })

    report = {
        "target_info": {
            "id": target.id,
            "domain": target.domain,
            "created_at": target.created_at
        },
        "scan_summary": {
            "total_scans_executed": len(scans),
            "scans": [{"id": s.id, "scan_type": s.scan_type, "status": s.status} for s in scans]
        },
        "vulnerability_statistics": vuln_summary,
        "vulnerabilities": vuln_list,
        "assessment_status": "Completed"
    }
    
    return {
        "status": "success",
        "message": "Consolidated bug bounty report generated successfully",
        "data": report
    }