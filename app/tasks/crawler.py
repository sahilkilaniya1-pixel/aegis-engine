import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from celery import shared_task
from app.database import SessionLocal
from app.models import Scan, Target

@shared_task(bind=True, name="crawler_scan_task")
def run_crawler_scan(self, scan_id: int, target_id: int, target_url: str):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        db.close()
        return {"status": "error", "message": "Scan not found"}
    
    scan.status = "running"
    db.commit()
    
    visited_urls = set()
    urls_to_visit = [target_url]
    domain = urlparse(target_url).netloc
    discovered_endpoints = []
    
    try:
        # Simple recursive crawler (Max limit: 30 pages to prevent infinite loops)
        while urls_to_visit and len(visited_urls) < 30:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
                
            visited_urls.add(current_url)
            
            try:
                response = requests.get(current_url, timeout=5, verify=False)
                if response.status_code != 200:
                    continue
                
                discovered_endpoints.append(current_url)
                
                # Parse HTML to find links and forms
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(current_url, link['href'])
                    parsed_link = urlparse(absolute_url)
                    
                    # Sirf same domain ke links crawl karein
                    if parsed_link.netloc == domain and absolute_url not in visited_urls:
                        if absolute_url not in urls_to_visit:
                            urls_to_visit.append(absolute_url)
                            
            except requests.RequestException:
                continue
        
        # Save scan results
        scan.status = "completed"
        scan.results = {
            "total_endpoints_discovered": len(discovered_endpoints),
            "endpoints": discovered_endpoints[:50]  # Store first 50 endpoints
        }
        db.commit()
        
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        db.commit()
    finally:
        db.close()
        
    return {"status": "completed", "endpoints_found": len(discovered_endpoints)}