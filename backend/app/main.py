import asyncio
import os
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
import requests
from requests.auth import HTTPBasicAuth
from pydantic import BaseModel

from app.schemas import ScanRequest, ScanResult
from app.services.phase1_domain import Phase1DomainScanner
from app.services.mcp_agent import AutonomousMCPAgent
from app.services.mcp_server import mcp_server, MCP_TOOLS
from app.services.job_manager import job_manager
from app.services.proxy_rotator import proxy_rotator
from app.cache import get_cached_scan
from app.remediation import REMEDIATION_PLAYBOOKS

app = FastAPI(
    title="ReconFlow AI — EASM Agent API",
    description="Autonomous External Attack Surface Management & Threat Intelligence Engine (100% Open-Source Search)",
    version="2.0.0"
)

# Enable CORS for Next.js frontend (strictly compliant with allow_credentials=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = Phase1DomainScanner()
mcp_agent = AutonomousMCPAgent()


@app.get("/")
def root_index():
    return {
        "status": "ok",
        "service": "ReconFlow AI — EASM Agent API (100% Free & Open-Source)",
        "documentation": "/docs",
        "health": "/health",
        "endpoints": [
            "/api/scan",
            "/api/scan/jobs",
            "/api/mcp/rpc",
            "/api/mcp/tools",
            "/api/mcp/chat",
            "/api/engines",
            "/api/remediation"
        ]
    }

@app.get("/health")
@app.get("/healthz")
@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "ReconFlow AI EASM Agent",
        "version": "1.0.0",
        "mcp_enabled": True
    }


def _execute_background_scan(job_id: str, req: ScanRequest):
    try:
        job_manager.update_job(job_id, status="running", progress=10)
        res = scanner.scan(
            target=req.domain,
            use_cache=req.use_cache,
            enable_phase2=req.enable_phase2,
            custom_dorks=req.custom_dorks,
            enabled_vectors=req.enabled_vectors,
            protocol=req.protocol or "rest"
        )
        job_manager.update_job(job_id, status="completed", progress=100, result=res)
    except Exception as exc:
        job_manager.update_job(job_id, status="failed", progress=0, error=str(exc))

@app.post("/api/scan", response_model=ScanResult)
async def run_recon_scan(req: ScanRequest):
    """
    Non-blocking reconnaissance scan endpoint.
    Executes scan off the main event loop via asyncio.to_thread to maintain high concurrency.
    """
    if not req.domain or not req.domain.strip():
        raise HTTPException(status_code=400, detail="Target domain must not be empty.")
    
    result = await asyncio.to_thread(
        scanner.scan,
        target=req.domain,
        use_cache=req.use_cache,
        enable_phase2=req.enable_phase2,
        custom_dorks=req.custom_dorks,
        enabled_vectors=req.enabled_vectors,
        protocol=req.protocol or "rest"
    )
    return result

@app.post("/api/scan/jobs")
async def create_scan_job(req: ScanRequest, bg_tasks: BackgroundTasks):
    """
    Asynchronous Scan Dispatch: Returns a task ID in <5ms.
    Prevents 30s gateway timeouts on Render/Vercel proxies for deep scans.
    """
    if not req.domain or not req.domain.strip():
        raise HTTPException(status_code=400, detail="Target domain must not be empty.")
    job_id = job_manager.create_job(req.domain, protocol=req.protocol or "rest")
    bg_tasks.add_task(_execute_background_scan, job_id, req)
    return {
        "status": "pending",
        "job_id": job_id,
        "target": req.domain,
        "poll_url": f"/api/scan/jobs/{job_id}"
    }

@app.get("/api/scan/jobs/{job_id}")
def get_scan_job_status(job_id: str):
    """Poll the status or final result of an asynchronous reconnaissance job."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return job

# -------------------------------------------------------------------------
# Model Context Protocol (MCP) Endpoints — JSON-RPC 2.0
# -------------------------------------------------------------------------
@app.post("/api/mcp/rpc")
async def mcp_json_rpc(request: Request):
    """Standard JSON-RPC 2.0 Model Context Protocol endpoint."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON-RPC payload")
    return mcp_server.handle_json_rpc(payload)

@app.get("/api/mcp/tools")
def list_mcp_tools():
    """Returns declared MCP tools with input schemas."""
    return {"tools": MCP_TOOLS}

class MCPChatRequest(BaseModel):
    domain: str
    message: str
    existing_nodes: Optional[list] = []

@app.post("/api/mcp/chat")
async def mcp_agent_chat(req: MCPChatRequest):
    """
    Autonomous Recon Agent Chat Endpoint using real MCP tools.
    """
    if not req.message or not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    target_domain = req.domain or "vulnweb.com"
    return await asyncio.to_thread(
        mcp_agent.execute_agent_chat,
        target=target_domain,
        user_message=req.message,
        existing_nodes=req.existing_nodes
    )


@app.get("/api/cache/{domain}")
def get_cached_report(domain: str):
    cached = get_cached_scan(domain)
    if not cached:
        raise HTTPException(status_code=404, detail="No cached dossier found for this target domain.")
    return cached

@app.get("/api/remediation")
def get_all_remediations():
    return REMEDIATION_PLAYBOOKS

@app.get("/api/remediation/{category}")
def get_category_remediation(category: str):
    cat_upper = category.upper()
    if cat_upper in REMEDIATION_PLAYBOOKS:
        return REMEDIATION_PLAYBOOKS[cat_upper]
    raise HTTPException(status_code=404, detail="Category not found.")

@app.get("/api/toolchain")
@app.get("/api/engines")
def toolchain_status():
    """Report active open-source reconnaissance engines and proxy rotation status."""
    engines = {
        "Google (Search)": True,
        "DuckDuckGo (Web)": True,
        "DuckDuckGo News": True,
        "DuckDuckGo Videos": True,
        "Certificate Transparency (crt.sh)": True,
    }
    proxy_status = proxy_rotator.get_status()
    return {
        "engines": engines,
        "tools": engines,
        "mode": "100% Open-Source Intelligence (No API Keys Required)",
        "active_count": len(engines),
        "pipeline_ready": True,
        "pipeline_tools": list(engines.keys()),
        "proxy_rotation": proxy_status,
    }

@app.get("/api/proxies/status")
def get_proxies_status():
    """Returns the current proxy rotation pool health and metrics."""
    return proxy_rotator.get_status()

@app.post("/api/proxies/refresh")
def refresh_proxy_pool():
    """Forces an immediate reload and validation of candidate proxies."""
    proxy_rotator.reload_proxies(background_verify=True)
    return {
        "status": "ok",
        "message": "Proxy pool refresh and validation triggered in background.",
        "pool": proxy_rotator.get_status()
    }

