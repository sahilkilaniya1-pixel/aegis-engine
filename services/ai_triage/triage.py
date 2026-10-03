cat << 'EOF' > services/ai_triage/triage.py
from pydantic import BaseModel
from typing import Optional

class AlertPayload(BaseModel):
    target_url: str
    status_code: int
    raw_response: str
    vulnerability_type: str

class TriageResult(BaseModel):
    target_url: str
    is_valid: bool
    confidence_score: float
    reasoning: str

class SecurityTriageEngine:
    def __init__(self, confidence_threshold: float = 0.75):
        self.threshold = confidence_threshold

    async def evaluate_finding(self, payload: AlertPayload) -> TriageResult:
        is_valid = False
        confidence = 0.0

        if payload.status_code == 200 and "error" not in payload.raw_response.lower():
            confidence = 0.85
            is_valid = True
            reason = "Valid response pattern detected without standard web error signatures."
        else:
            confidence = 0.20
            reason = "Response indicates potential false positive or blocked request."

        return TriageResult(
            target_url=payload.target_url,
            is_valid=(confidence >= self.threshold),
            confidence_score=confidence,
            reasoning=reason
        )
EOF