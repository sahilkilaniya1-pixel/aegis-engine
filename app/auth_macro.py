from fastapi import APIRouter, HTTPException
import httpx
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import re

macro_router = APIRouter(prefix="/macro", tags=["Auth & Macro Engine"])

class MacroStep(BaseModel):
    url: str
    method: str
    headers: Dict[str, str] = {}
    data: Dict[str, Any] = {}
    extract_regex: Optional[str] = None 
    extract_var_name: Optional[str] = None

class MacroExecutionRequest(BaseModel):
    steps: List[MacroStep]

@macro_router.post("/execute")
async def execute_auth_macro(payload: MacroExecutionRequest):
    session_cookies = {}
    extracted_variables = {}
    execution_logs = []
    
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            for index, step in enumerate(payload.steps):
                
                # 1. Substitute variables in URL, headers, or data if extracted earlier
                url = step.url
                headers = step.headers.copy()
                data = step.data.copy()
                
                for var_name, var_val in extracted_variables.items():
                    placeholder = f"${{{var_name}}}"
                    url = url.replace(placeholder, str(var_val))
                    
                    # Headers and Data mein bhi substitution apply karein
                    for h_key, h_val in headers.items():
                        if isinstance(h_val, str):
                            headers[h_key] = h_val.replace(placeholder, str(var_val))
                    for d_key, d_val in data.items():
                        if isinstance(d_val, str):
                            data[d_key] = d_val.replace(placeholder, str(var_val))
                
                # 2. Har step ko sequential execute karte hain aur cookies maintain karte hain
                response = await client.request(
                    method=step.method,
                    url=url,
                    headers=headers,
                    data=data,
                    cookies=session_cookies
                )
                
                # 3. Session cookies update karein agle requests ke liye
                session_cookies.update(response.cookies)
                
                # 4. Extract dynamic tokens/variables if rule is provided
                if step.extract_regex and step.extract_var_name:
                    match = re.search(step.extract_regex, response.text)
                    if match:
                        extracted_variables[step.extract_var_name] = match.group(1)
                
                execution_logs.append({
                    "step": index + 1,
                    "url": url,
                    "status_code": response.status_code
                })
                
        return {
            "status": "macro_executed_successfully",
            "extracted_variables": extracted_variables,
            "active_session_cookies": list(session_cookies.keys()),
            "logs": execution_logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))