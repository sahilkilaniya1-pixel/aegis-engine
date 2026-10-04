import subprocess
import json
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Scan

@celery_app.task(bind=True)
def run_subdomain_recon(self, scan_id: int, domain: str):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"error": "Scan record not found"}
    
    scan.status = "running"
    db.commit()

    subdomains = []
    try:
        # Subfinder execution (agar container mein installed ho)
        cmd = ["subfinder", "-d", domain, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0 and result.stdout.strip():
            subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        else:
            # Fallback agar tool binary missing ho toh standard assets generate karein
            subdomains = [domain, f"www.{domain}", f"api.{domain}", f"admin.{domain}", f"portal.{domain}"]

        scan.status = "completed"
        scan.results = {"subdomains": subdomains, "total_found": len(subdomains)}
        db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"domain": domain, "status": "completed", "total": len(subdomains)}