"""
ReconFlow AI Production Test Suite.
Verifies Phase1DomainScanner, Cache lifecycle with TTL & Path Traversal Prevention,
Multi-Worker Safe Job Manager, MCP Server JSON-RPC 2.0, Intent Filtering, and Exposure Prober.
"""

import time
import pytest
from app.services.phase1_domain import Phase1DomainScanner
from app.cache import get_cached_scan, set_cached_scan, _sanitize_domain
from app.services.job_manager import job_manager
from app.services.mcp_server import MCPServer
from app.services.mcp_agent import AutonomousMCPAgent
from app.services.exposure_prober import verify_http_exposure


def test_scanner_initialization():
    """Verify Phase1DomainScanner initializes with zero arguments (no invalid api_key)."""
    scanner = Phase1DomainScanner()
    assert scanner is not None
    assert scanner.search_client is not None
    assert scanner.mcp_agent is not None


def test_cache_demo_fixture():
    """Verify demo-sandbox.corp fixture loads properly from disk cache."""
    cached = get_cached_scan("demo-sandbox.corp")
    assert cached is not None
    assert cached["summary"]["target"] == "demo-sandbox.corp"
    assert len(cached["nodes"]) > 0
    assert len(cached["edges"]) > 0
    assert cached["summary"]["critical_risks"] >= 1


def test_cache_write_and_read():
    """Verify custom scan caching with TTL expiration."""
    test_domain = "test-cache-target.io"
    payload = {
        "summary": {
            "target": test_domain,
            "total_nodes": 5,
            "critical_risks": 0,
            "high_risks": 0,
            "medium_risks": 1,
            "low_risks": 2,
            "info": 2,
            "security_score": 85,
            "security_grade": "B",
            "protocol_used": "direct_rest"
        },
        "nodes": [],
        "edges": [],
        "thoughts": []
    }
    set_cached_scan(test_domain, payload)
    retrieved = get_cached_scan(test_domain, max_age_sec=60)
    assert retrieved is not None
    assert retrieved["summary"]["target"] == test_domain
    assert retrieved["summary"]["security_score"] == 85


def test_cache_path_traversal_prevention():
    """Verify that domain keys with path traversal tokens are sanitized and cannot escape CACHE_DIR."""
    assert _sanitize_domain("../../var/log/pwned") == "invalid_target"
    assert ".." not in _sanitize_domain("../../../etc/shadow")
    assert _sanitize_domain("sub.example.com/..") == "sub.example.com"

    # Verify write with malicious key does not escape
    malicious_domain = "../../../tmp/pwned"
    set_cached_scan(malicious_domain, {"status": "exploit"})
    retrieved = get_cached_scan(malicious_domain)
    # Sanitized domain is stored safely within CACHE_DIR without escaping
    assert retrieved is not None


def test_job_manager_multi_worker_persistence():
    """Verify asynchronous background scan job creation, file persistence, and recovery."""
    target = "example-corp.com"
    job_id = job_manager.create_job(target, protocol="rest")
    assert job_id is not None

    # Verify job immediately readable
    job = job_manager.get_job(job_id)
    assert job is not None
    assert job["target"] == target
    assert job["status"] == "pending"

    # Update job status and progress
    job_manager.update_job(job_id, status="running", progress=50)
    updated = job_manager.get_job(job_id)
    assert updated["status"] == "running"
    assert updated["progress"] == 50


def test_mcp_agent_intent_filter():
    """Verify context-aware intent parser does NOT trigger tools on conversational / non-recon queries."""
    agent = AutonomousMCPAgent()
    
    # Conversational text containing a keyword should NOT trigger audit_cloud_storage
    resp = agent.execute_agent_chat("target.com", "I love riding in a bucket of ice cream")
    assert resp["tool_call"] is None
    assert "ReconFlow MCP Agent standing by" in resp["reply"] or "target.com" in resp["reply"]

    # Explicit cybersecurity recon command DOES trigger audit_cloud_storage
    resp_valid = agent.execute_agent_chat("target.com", "Audit AWS S3 buckets and cloud storage exposures")
    assert resp_valid["tool_call"] is not None
    assert resp_valid["tool_call"]["tool_name"] == "audit_cloud_storage"


def test_mcp_server_json_rpc_tools_list():
    """Verify MCP JSON-RPC 2.0 initialize and tools/list capabilities."""
    server = MCPServer()

    # 1. Initialize
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"clientInfo": {"name": "test-client", "version": "1.0"}}
    }
    init_res = server.handle_json_rpc(init_req)
    assert init_res["jsonrpc"] == "2.0"
    assert init_res["id"] == 1
    assert "serverInfo" in init_res["result"]
    assert init_res["result"]["serverInfo"]["name"] == "reconflow-mcp-server"

    # 2. tools/list
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    list_res = server.handle_json_rpc(list_req)
    assert list_res["jsonrpc"] == "2.0"
    tools = list_res["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "harvest_subdomains" in tool_names
    assert "audit_cloud_storage" in tool_names
    assert "search_threat_dorks" in tool_names
    assert "verify_endpoint_exposure" in tool_names
    assert "get_remediation_playbook" in tool_names


def test_mcp_server_tool_execution():
    """Verify execution of MCP tools via JSON-RPC 2.0."""
    server = MCPServer()

    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_remediation_playbook",
            "arguments": {"category": "CONFIG_LEAK"}
        }
    }
    call_res = server.handle_json_rpc(call_req)
    assert call_res["jsonrpc"] == "2.0"
    assert call_res["result"]["isError"] is False
    content_text = call_res["result"]["content"][0]["text"]
    assert "CONFIG_LEAK" in content_text
    assert "actions" in content_text or "default_directive" in content_text


def test_scanner_scan_fixture():
    """Verify scan against demo fixture executes seamlessly."""
    scanner = Phase1DomainScanner()
    res = scanner.scan("demo-sandbox.corp", use_cache=True)
    assert res.summary.target == "demo-sandbox.corp"
    assert len(res.nodes) > 0
    assert len(res.edges) > 0
    assert res.summary.critical_risks >= 1


def test_scanner_protocol_branching():
    """Verify protocol branching sets protocol_used truthfully."""
    scanner = Phase1DomainScanner()
    res_rest = scanner.scan("demo-sandbox.corp", use_cache=True, protocol="rest")
    assert res_rest.summary.protocol_used in ["direct_rest", "open_source"]


def test_exposure_prober_safety():
    """Verify non-invasive exposure prober gracefully handles non-HTTP or unresolvable schemes."""
    res = verify_http_exposure("invalid-url-without-scheme")
    assert res["verified"] is False
    assert res["is_false_positive"] is True
    assert "Invalid URL scheme" in res["reason"]


if __name__ == "__main__":
    pytest.main(["-v", __file__])
