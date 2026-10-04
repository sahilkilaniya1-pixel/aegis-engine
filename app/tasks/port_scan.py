import socket
import subprocess
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Scan

@celery_app.task(bind=True)
def run_port_scan(self, scan_id: int, domain: str):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"error": "Scan record not found"}
    
    scan.status = "running"
    db.commit()

    open_ports = []
    common_ports = [21, 22, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    try:
        # Resolve domain to IP first
        target_ip = socket.gethostbyname(domain)
        
        # Fast socket-based port checking for common ports
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                service_name = "http" if port in [80, 8080, 8443] else ("https" if port == 443 else "unknown")
                open_ports.append({"port": port, "status": "open", "service": service_name})
            s.close()

        scan.status = "completed"
        scan.results = {
            "target_ip": target_ip,
            "open_ports": open_ports,
            "total_open": len(open_ports)
        }
        db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"domain": domain, "status": "completed", "open_ports_count": len(open_ports)}