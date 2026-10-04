import httpx
from fastapi import APIRouter, Request, Response
from app.database import SessionLocal
from app.models import Vulnerability  # Ya aap ek naya ProxyLog model bana sakte hain

proxy_router = APIRouter(prefix="/proxy", tags=["Intercepting Proxy"])

@proxy_router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_handler(request: Request, path: str):
    # Target destination (Aap dynamic target bhi pass kar sakte hain)
    target_base_url = "http://example.com"  # Test target ya dynamic routing
    url = f"{target_base_url}/{path}"
    
    # Request details capture karein
    headers = dict(request.headers)
    # Host header update karna zaroori hota hai proxy ke liye
    headers.pop("host", None)
    
    body = await request.body()
    method = request.method
    params = request.query_params
    
    # Database session open karein logging ke liye
    db = SessionLocal()
    try:
        # Asynchronous HTTP client ka use karke request forward karein
        async with httpx.AsyncClient(verify=False) as client:
            proxy_response = await client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                content=body,
                follow_redirects=True
            )
            
        # TODO: Yahan request aur response ko database mein log kar sakte hain
        
        # Client ko response return karein
        return Response(
            content=proxy_response.content,
            status_code=proxy_response.status_code,
            headers=dict(proxy_response.headers)
        )
    except Exception as e:
        return Response(content=str(e), status_code=500)
    finally:
        db.close()