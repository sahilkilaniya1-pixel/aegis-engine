# 🛡️ AegisEngine v2.0
> **Autonomous Hybrid Vulnerability Scanner & AI-Assisted Triage System**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**AegisEngine** is a high-concurrency security scanner designed to bridge the gap between rapid network reconnaissance and accurate vulnerability validation. By coupling a low-latency Go scanning engine with an asynchronous Python FastAPI triage microservice, AegisEngine automates candidate payload testing and filters out false positives before security teams review alerts.

---

## 🏗️ System Architecture

```text
               +----------------------------------+
               |        AegisEngine CLI (Go)      |
               | - Worker Pools & Concurrency    |
               | - HTTP Recon & Target Discovery  |
               +----------------+-----------------+
                                |
                                | HTTP POST (Payload & Metadata)
                                v
               +----------------------------------+
               |     AI Triage Service (FastAPI)  |
               | - Payload Validation             |
               | - Playwright DOM Proof Engine    |
               | - Contextual Risk Scoring        |
               +----------------+-----------------+
                                |
                                v
                   [ Formatted Security Alerts ]