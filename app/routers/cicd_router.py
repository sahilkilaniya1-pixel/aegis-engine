from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Vulnerability, Target

cicd_router = APIRouter(prefix="/api/v1/cicd", tags=["DevSecOps CI/CD"])

# Enterprise API Key validation simulation
API_KEY_SECRET = "aegis-enterprise-ci-key-9988"

def verify_ci_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY_SECRET:
        raise HTTPException(status_code=403, detail="Invalid or missing Enterprise CI/CD API Key")
    return True

@cicd_router.post("/gate-check/{target_id}")
def cicd_vulnerability_gate(target_id: int, threshold_severity: str = "High", db: Session = Depends(get_db), authorized: bool = Depends(verify_ci_key)):
    """
    CI/CD Quality Gate: Returns non-zero exit/failure status if vulnerabilities 
    exceed the defined severity threshold (e.g., Critical or High).
    """
    vulns = db.query(Vulnerability).filter(
        Vulnerability.target_id == target_id,
        Vulnerability.severity.in_([threshold_severity, "Critical"])
    ).all()

    if vulns:
        return {
            "status": "BUILD_FAILED",
            "message": f"Security Gate Failed! Found {len(vulns)} {threshold_severity}+ vulnerabilities.",
            "vulnerabilities": [{"title": v.title, "severity": v.severity, "cwe": v.cwe} for v in vulns]
        }
    
    return {
        "status": "BUILD_PASSED",
        "message": "No critical security roadblocks found. Pipeline approved."
    }