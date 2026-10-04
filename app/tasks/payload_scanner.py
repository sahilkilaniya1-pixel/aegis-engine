import os
import glob
import requests
from celery import shared_task
from app.database import SessionLocal
from app.models import Scan, Vulnerability

WORDLIST_DIR = os.getenv("WORDLIST_DIR", "/app/wordlists")

def load_all_payloads_from_directory(directory_path):
    """Wordlists folder se sabhi .txt files se payloads read karega"""
    payloads = {"xss": [], "sqli": []}
    
    if not os.path.exists(directory_path):
        return payloads
        
    # Folder ki saari .txt files ko search karein
    txt_files = glob.glob(os.path.join(directory_path, "*.txt"))
    
    for file_path in txt_files:
        filename = os.path.basename(file_path).lower()
        file_payloads = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith("#"):
                        file_payloads.append(clean_line)
        except Exception:
            continue
            
        # File name ke hisab se categorize karein
        if "xss" in filename:
            payloads["xss"].extend(file_payloads)
        elif "sqli" in filename or "sql" in filename:
            payloads["sqli"].extend(file_payloads)
        else:
            # Agar koi general file hai toh dono mein include kar sakte hain
            payloads["xss"].extend(file_payloads)
            payloads["sqli"].extend(file_payloads)
            
    return payloads

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
    
    # Directory se saari files ke payloads load karein
    all_payloads = load_all_payloads_from_directory(WORDLIST_DIR)
    xss_payloads = all_payloads["xss"]
    sqli_payloads = all_payloads["sqli"]
    
    # Fallback agar koi payload na mile
    if not xss_payloads:
        xss_payloads = ["<script>alert(1)</script>"]
    if not sqli_payloads:
        sqli_payloads = ["' OR '1'='1"]
    
    try:
        # 1. XSS Testing
        for payload in xss_payloads:
            test_url = f"{target_url}?q={payload}"
            try:
                response = requests.get(test_url, timeout=4, verify=False)
                if payload in response.text:
                    detected_vulns.append({
                        "title": "Reflected Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "description": f"Payload matched from custom wordlists: {payload}",
                        "matched_at": test_url
                    })
                    break
            except requests.RequestException:
                continue
        
        # 2. SQLi Testing
        for payload in sqli_payloads:
            test_url = f"{target_url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=4, verify=False)
                sql_errors = [
                    "sql syntax", "mysql_fetch", "syntax error", 
                    "unclosed quotation mark", "ora-01756", 
                    "postgresql error", "sqlite3.operationalerror"
                ]
                if any(err in response.text.lower() for err in sql_errors):
                    detected_vulns.append({
                        "title": "SQL Injection (SQLi)",
                        "severity": "Critical",
                        "description": f"Database error triggered with custom wordlist payload: {payload}",
                        "matched_at": test_url
                    })
                    break
            except requests.RequestException:
                continue

        # Save vulnerabilities
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
        scan.results = {
            "vulnerabilities_found": len(detected_vulns),
            "custom_xss_loaded": len(xss_payloads),
            "custom_sqli_loaded": len(sqli_payloads)
        }
        db.commit()
        
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"status": "completed", "vulnerabilities_found": len(detected_vulns)}