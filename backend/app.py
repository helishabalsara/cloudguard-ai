"""
CloudGuard AI – FastAPI backend.
Serves the REST API and the web dashboard.
"""

import json
import os
import sys

import yaml
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.analyzers.misconfiguration_detector import run_scan, get_mock_findings
from backend.rag.remediation_engine import ask

app = FastAPI(
    title="CloudGuard AI",
    description="Multi-cloud threat detection and posture management platform",
    version="1.0.0",
)

# Load config
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
with open(CONFIG_PATH) as fh:
    CONFIG = yaml.safe_load(fh)

# In-memory findings store (replace with DB in production)
_findings_store: dict = {}

# Static files & templates
_static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "static")
_templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "templates")

if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

templates = Jinja2Templates(directory=_templates_dir)


# --- Models ---

class ScanRequest(BaseModel):
    provider: str = "aws"
    mock: bool = False

class ChatRequest(BaseModel):
    message: str


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/scan")
async def scan(req: ScanRequest):
    if req.mock:
        result = get_mock_findings()
    else:
        result = run_scan(req.provider, CONFIG)
    _findings_store["latest"] = result
    return result


@app.get("/api/findings")
async def get_findings():
    if not _findings_store.get("latest"):
        return get_mock_findings()
    return _findings_store["latest"]


@app.post("/api/chat")
async def chat(req: ChatRequest):
    findings = _findings_store.get("latest", {}).get("findings", [])
    response = ask(req.message, findings, CONFIG)
    return response


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


if __name__ == "__main__":
    host = CONFIG.get("server", {}).get("host", "0.0.0.0")
    port = CONFIG.get("server", {}).get("port", 8000)
    debug = CONFIG.get("server", {}).get("debug", False)
    print(f"CloudGuard AI starting on http://{host}:{port}")
    uvicorn.run("backend.app:app", host=host, port=port, reload=debug)
