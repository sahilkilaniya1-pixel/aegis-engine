from fastapi import APIRouter, Request
import datetime

oob_router = APIRouter(prefix="/oob", tags=["OOB Collaborator"])

# Temporary storage (Aap ise Database mein bhi save kar sakte hain)
oob_interactions = []

@oob_router.api_route("/ping/{unique_token}", methods=["GET", "POST", "PUT", "DELETE"])
async def receive_oob_callback(unique_token: str, request: Request):
    client_ip = request.client.host
    headers = dict(request.headers)
    body = await request.body()
    
    # Interaction record karein
    interaction = {
        "token": unique_token,
        "source_ip": client_ip,
        "method": request.method,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "headers": headers,
        "body": body.decode(errors="ignore")
    }
    
    oob_interactions.append(interaction)
    return {"status": "recorded", "token": unique_token}

@oob_router.get("/interactions/{unique_token}")
async def check_interaction(unique_token: str):
    # Check karein ki specific token par koi hit aaya hai ya nahi
    matched = [i for i in oob_interactions if i["token"] == unique_token]
    return {"hit_count": len(matched), "interactions": matched}