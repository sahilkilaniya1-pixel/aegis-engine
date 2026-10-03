from fastapi import APIRouter, Request
import logging

router = APIRouter(prefix="/oast", tags=["Out-of-Band Listener"])
logging.basicConfig(level=logging.INFO)

# Callback interaction storage
OAST_LOGS = []

@router.all("/callback/{token}")
async def handle_callback(token: str, request: Request):
    client_ip = request.client.host
    headers = dict(request.headers)
    
    log_entry = {
        "token": token,
        "ip": client_ip,
        "method": request.method,
        "headers": headers
    }
    
    OAST_LOGS.append(log_entry)
    logging.info(f"[OAST Interaction] Token: {token} from IP: {client_ip}")
    
    return {"status": "recorded", "token": token}