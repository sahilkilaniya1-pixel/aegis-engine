from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sys
import os

# Add root directory to python path for internal imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from services.ai_triage.triage import SecurityTriageEngine, AlertPayload, TriageResult

app = FastAPI(
    title="AegisEngine API",
    version="2.0",
    description="Autonomous AI & Security Triage Engine"
)

triage_engine = SecurityTriageEngine()

@app.get("/")
def read_root():
    return {"status": "online", "service": "AegisEngine Security API"}

@app.post("/api/v1/scan-and-verify", response_model=TriageResult)
async def scan_and_verify(payload: AlertPayload):
    try:
        result = await triage_engine.evaluate_finding(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))