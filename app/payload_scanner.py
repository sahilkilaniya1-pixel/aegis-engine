import requests
from celery import shared_task
from app.database import SessionLocal
from app.models import Scan, Vulnerability

# Basic safe test payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(document.domain)</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL, NULL--"
]

@shared_task(bind=True, name="payload_scan_task")
def run_payload_scan(self, scan_id: int, target_id: int, target_url: str):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"status": "error", "message": "Scan not found"}
    
    scan.status = "running"
    db.commit()
    
    detected_vulns = []
    
    try:
        # 1. XSS Testing Simulation
        for payload in XSS_PAYLOADS:
            test_url = f"{target_url}?q={payload}"
            response = requests.get(test_url, timeout=5, verify=False)
            if payload in response.text:
                detected_vulns.append({
                    "title": "Reflected Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "description": f"Payload reflected in response without proper sanitization: {payload}",
                    "matched_at": test_url
                })
                break  
        
        # 2. SQLi Testing Simulation
        for payload in SQLI_PAYLOADS:
            test_url = f"{target_url}?id={payload}"
            response = requests.get(test_url, timeout=5, verify=False)
            # Common database error signatures
            sql_errors = ["sql syntax", "mysql_fetch", "syntax error", "unclosed quotation mark"]
            if any(err in response.text.lower() for err in sql_errors):
                detected_vulns.append({
                    "title": "SQL Injection (SQLi)",
                    "severity": "Critical",
                    "description": f"Database error detected with payload: {payload}",
                    "matched_at": test_url
                })
                break

        # Save vulnerabilities to database
        for v_data in detected_vulns:
            vuln = Vulnerability(
                target_id=target_id,
                title=v_data["title"],
                severity=v_data["severity"],
                description=v_data["description"],
                matched_at=v_data["matched_at"]
            )
            db.add(vuln)
        
        scan.status = "completed"
        scan.results = {"vulnerabilities_found": len(detected_vulns)}
        db.commit()
        
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"status": "completed", "vulnerabilities_found": len(detected_vulns)}