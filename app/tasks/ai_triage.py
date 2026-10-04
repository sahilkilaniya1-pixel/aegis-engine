import os
import openai
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Scan, Vulnerability

@celery_app.task(bind=True)
def run_ai_triage(self, scan_id: int, target_id: int):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"error": "Scan record not found"}
    
    scan.status = "running"
    db.commit()

    try:
        scan_data = scan.results or {}
        
        # Simulating or calling LLM for Triage analysis
        # Agar aap OpenAI API key use karna chahte hain toh os.getenv("OPENAI_API_KEY") use kar sakte hain
        ai_prompt = f"Analyze the following scan results for security vulnerabilities and filter out false positives: {scan_data}"
        
        # Fallback intelligent triage logic agar API key configure na ho
        identified_vulns = []
        open_ports = scan_data.get("open_ports", [])
        
        for p in open_ports:
            port = p.get("port")
            if port in [21, 23]:
                identified_vulns.append({
                    "title": f"Insecure Plaintext Protocol (Port {port})",
                    "severity": "Medium",
                    "description": f"Port {port} is open, which allows unencrypted data transmission."
                })
            elif port in [3306, 5432]:
                identified_vulns.append({
                    "title": f"Database Port Exposed (Port {port})",
                    "severity": "High",
                    "description": f"Database port {port} is directly exposed to the internet."
                })

        # Save identified vulnerabilities to DB
        for vuln in identified_vulns:
            db_vuln = Vulnerability(
                target_id=target_id,
                title=vuln["title"],
                severity=vuln["severity"],
                description=vuln["description"],
                raw_evidence=scan_data
            )
            db.add(db_vuln)

        scan.status = "completed"
        scan.results = {
            "triage_status": "success",
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
        
    return {"status": "completed", "target_id": target_id}