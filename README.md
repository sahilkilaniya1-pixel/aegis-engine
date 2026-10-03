# AegisEngine

> **Autonomous AI-Driven Vulnerability Scanner & Triage Engine**  
> *Combines high-concurrency network reconnaissance in Go with LLM-powered false-positive reduction in Python.*

## Features
- Go Scanner Core: Multi-threaded async network checks.
- AI Triage Layer: False positive reduction with LLM reasoning.
- Playwright Browser Verification: Automatic screenshot proof for DOM/XSS vulnerabilities.
- OAST Listener: Out-of-band callback handler for Blind vulnerabilities.

## Quick Start
1. Install Dependencies: pip install -r requirements.txt
2. Run API Server: uvicorn services.api.main:app --reload --port 8000
3. Run Go CLI: go run cmd/aegis-cli/main.go
