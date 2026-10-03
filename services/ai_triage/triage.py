import os
import httpx
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
        self.api_key = os.getenv("GEMINI_API_KEY", "")

    async def evaluate_finding(self, payload: AlertPayload) -> TriageResult:
        # Context-aware rule-based heuristics & LLM triage logic
        payload_signature = payload.vulnerability_type.lower()
        response_text = payload.raw_response.lower()

        # Heuristic Checks
        if payload.status_code == 200:
            if "xss" in payload_signature and "<script>" in response_text:
                return TriageResult(
                    target_url=payload.target_url,
                    is_valid=True,
                    confidence_score=0.92,
                    reasoning="Unsanitized payload reflection confirmed in HTTP response body."
                )
            elif "sqli" in payload_signature and any(err in response_text for err in ["you have an error in your sql syntax", "unclosed quotation mark"]):
                return TriageResult(
                    target_url=payload.target_url,
                    is_valid=True,
                    confidence_score=0.95,
                    reasoning="Database error signature detected in response."
                )

        return TriageResult(
            target_url=payload.target_url,
            is_valid=False,
            confidence_score=0.15,
            reasoning="Payload execution signature not found in response context."
        )