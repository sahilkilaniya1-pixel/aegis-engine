from fastapi import APIRouter, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_db
from app.models import OOBInteractionModel

oob_router = APIRouter(prefix="/oob", tags=["OOB Collaborator"])

@oob_router.api_route("/ping/{unique_token}", methods=["GET", "POST", "PUT", "DELETE"])
async def receive_oob_callback(unique_token: str, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)
    body = await request.body()
    
    # Database model instance create karke save karein
    interaction = OOBInteractionModel(
        token=unique_token,
        source_ip=client_ip,
        method=request.method,
        headers=headers,
        body=body.decode(errors="ignore")
    )
    
    db.add(interaction)
    await db.commit()
    await db.refresh(interaction)
    
    return {"status": "recorded", "token": unique_token}

@oob_router.get("/interactions/{unique_token}")
async def check_interaction(unique_token: str, db: AsyncSession = Depends(get_db)):
    # Database se specific token ke saare hits fetch karein
    result = await db.execute(
        select(OOBInteractionModel).where(OOBInteractionModel.token == unique_token)
    )
    hits = result.scalars().all()
    
    interactions_list = [
        {
            "id": hit.id,
            "token": hit.token,
            "source_ip": hit.source_ip,
            "method": hit.method,
            "timestamp": hit.timestamp.isoformat() if hit.timestamp else None,
            "headers": hit.headers,
            "body": hit.body
        }
        for hit in hits
    ]
    
    return {"hit_count": len(hits), "interactions": interactions_list}