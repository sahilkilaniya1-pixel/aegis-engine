import httpx
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Scan, Vulnerability

@celery_app.task(bind=True)
def run_active_vulnerability_scan(self, scan_id: int, target_id: int, domain: str):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"error": "Scan record not found"}
    
    scan.status = "running"
    db.commit()

    base_url = f"http://{domain}" if not domain.startswith("http") else domain
    identified_vulns = []

    try:
        with httpx.Client(timeout=6.0, follow_redirects=True) as client:
            response = client.get(base_url)
            headers = response.headers

            # Check 1: Missing Security Headers
            security_headers = ["content-security-policy", "strict-transport-security", "x-frame-options"]
            missing_headers = [h for h in security_headers if h not in headers]

            if missing_headers:
                identified_vulns.append({
                    "title": "Missing Recommended Security Headers",
                    "severity": "Low",
                    "description": f"The following security headers are missing: {', '.join(missing_headers)}"
                })

            # Check 2: Server Banner Disclosure
            if "server" in headers:
                identified_vulns.append({
                    "title": "Server Version Disclosure",
                    "severity": "Low",
                    "description": f"Server banner reveals software details: {headers['server']}"
                })

        # Save vulnerabilities to Database
        for vuln in identified_vulns:
            db_vuln = Vulnerability(
                target_id=target_id,
                title=vuln["title"],
                severity=vuln["severity"],
                description=vuln["description"],
                raw_evidence={"headers": dict(response.headers)}
            )
            db.add(db_vuln)

        scan.status = "completed"
        scan.results = {
            "active_scan_status": "success",
            "vulnerabilities_found": len(identified_vulns),
            "details": identified_vulns
        }
        db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"status": "completed", "target_id": target_id, "vulnerabilities": len(identified_vulns)}