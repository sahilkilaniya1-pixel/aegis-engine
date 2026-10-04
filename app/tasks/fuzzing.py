import httpx
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Scan, Vulnerability

@celery_app.task(bind=True)
def run_directory_fuzzing(self, scan_id: int, domain: str):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"error": "Scan record not found"}
    
    scan.status = "running"
    db.commit()

    # Common high-value paths/directories for bug bounty fuzzing
    common_paths = [
        "admin", "api", "login", "dashboard", "robots.txt", 
        "sitemap.xml", ".git/HEAD", "config.json", "backup.zip",
        "swagger.json", "api/docs", "graphql", "test.php"
    ]
    
    discovered_endpoints = []
    base_url = f"http://{domain}" if not domain.startswith("http") else domain

    try:
        # Using httpx for fast synchronous/asynchronous HTTP checking
        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            for path in common_paths:
                url = f"{base_url.rstrip('/')}/{path}"
                try:
                    response = client.get(url)
                    # Agar status code 200, 403, ya 401 aaye, matlab path exist karta hai
                    if response.status_code in [200, 401, 403]:
                        discovered_endpoints.append({
                            "path": f"/{path}",
                            "status_code": response.status_code,
                            "url": url
                        })
                except httpx.RequestError:
                    # Connection error ya timeout ko ignore karein
                    continue

        scan.status = "completed"
        scan.results = {
            "fuzzing_status": "success",
            "total_found": len(discovered_endpoints),
            "endpoints": discovered_endpoints
        }
        db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"status": "completed", "domain": domain, "found": len(discovered_endpoints)}