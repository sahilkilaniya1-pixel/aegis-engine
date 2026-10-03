from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from services.ai_triage.triage import SecurityTriageEngine, AlertPayload
from services.api.oast_listener import router as oast_router

app = FastAPI(
    title="AegisEngine Security Orchestrator",
    version="2.0.0",
    description="Autonomous AI & Browser Verification System"
)

# Include OAST Module
app.include_router(oast_router)

triage_engine = SecurityTriageEngine()

@app.post("/api/v1/scan-and-verify")
async def scan_and_verify(payload: AlertPayload):
    # 1. AI Triage Logic
    triage_result = await triage_engine.evaluate_finding(payload)
    
    return {
        "triage": triage_result,
        "status": "completed"
    }

@app.get("/health")
async def health_check():
    return {"status": "AegisEngine active"}