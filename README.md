# CloudGuard AI – Cloud Threat & Posture Platform

A platform that lets clients connect any cloud provider (AWS, Azure, GCP), automatically detects misconfigurations and security risks, and provides real-time agentic RAG-based remediation guidance with conversational infrastructure insights.

## Features
- Multi-cloud support: AWS, Azure, GCP
- Automatic misconfiguration detection (S3, IAM, networking, encryption, logging)
- Risk scoring per finding
- RAG-based remediation engine: asks natural-language questions, gets back step-by-step fix guides
- Real-time web dashboard
- REST API for integration into CI/CD pipelines

## Architecture
```
Cloud Providers (AWS / Azure / GCP)
        │
[ Cloud Connectors ]       ← boto3 / azure-sdk / google-cloud
        │
[ Misconfiguration Analyzer ] ← rule-based + ML risk scoring
        │
[ RAG Remediation Engine ]    ← vector DB + LLM for guided fixes
        │
[ REST API (FastAPI) ]        ← /scan, /findings, /chat
        │
[ Web Dashboard (HTML/JS) ]   ← real-time findings + chat UI
```

## Quick Start

### Install
```bash
pip install -r requirements.txt
```

### Configure cloud credentials
Edit `config.yaml` with your cloud provider credentials or set environment variables.

### Run the server
```bash
python backend/app.py
```

Then open `http://localhost:8000` in your browser.

### Scan AWS immediately
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "region": "us-east-1"}'
```

### Ask for remediation
```bash
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "How do I fix the S3 bucket public access issue?"}'
```

## Project Structure
```
CloudGuard-AI/
├── backend/
│   ├── app.py                          # FastAPI entry point
│   ├── cloud_connectors/
│   │   ├── aws_connector.py            # AWS checks via boto3
│   │   ├── azure_connector.py          # Azure checks
│   │   └── gcp_connector.py            # GCP checks
│   ├── analyzers/
│   │   ├── misconfiguration_detector.py
│   │   └── risk_scorer.py
│   └── rag/
│       ├── knowledge_base.py           # Remediation knowledge base
│       └── remediation_engine.py       # RAG query engine
├── frontend/
│   ├── templates/
│   │   └── index.html                  # Dashboard
│   └── static/
│       ├── css/style.css
│       └── js/app.js
├── config.yaml
├── requirements.txt
└── tests/
    └── test_analyzer.py
```

## Environment Variables
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_DEFAULT_REGION
AZURE_SUBSCRIPTION_ID
AZURE_TENANT_ID
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET
GOOGLE_APPLICATION_CREDENTIALS
OPENAI_API_KEY   # optional, for LLM-powered remediation
```
