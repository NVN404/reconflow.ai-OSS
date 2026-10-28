"""
Model Context Protocol (MCP) Server: Standard JSON-RPC 2.0 Implementation.
Implements the official Model Context Protocol specification for tool-use,
resources, and capability negotiation for ReconFlow AI.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from app.services.open_search_client import OpenSearchClient
from app.services.exposure_prober import verify_http_exposure
from app.remediation import get_remediation_for_category

logger = logging.getLogger("reconflow.mcp")

# MCP Protocol Definitions
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "reconflow-mcp-server",
    "version": "2.0.0",
    "description": "Autonomous External Attack Surface Management & OSINT Reconnaissance Server"
}

# Real MCP Tool Declarations with standard JSON Schema
MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "harvest_subdomains",
        "description": "Enumerate subdomains using Certificate Transparency (crt.sh) logs and passive multi-engine OSINT.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain name, e.g. 'example.com' or 'auth0.com'"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of subdomains to return (default: 30)",
                    "default": 30
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "search_threat_dorks",
        "description": "Execute targeted search queries against target perimeter for specific threat classes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain name"
                },
                "category": {
                    "type": "string",
                    "description": "Threat category to audit",
                    "enum": ["admin_gateways", "config_leaks", "api_docs", "credentials", "cloud_storage", "general"]
                }
            },
            "required": ["target", "category"]
        }
    },
    {
        "name": "audit_cloud_storage",
        "description": "Identify and audit public cloud buckets (AWS S3, GCP Storage) associated with the target domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target brand or domain"
                },
                "provider": {
                    "type": "string",
                    "description": "Cloud provider",
                    "enum": ["aws_s3", "gcp_storage", "azure_blob"],
                    "default": "aws_s3"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "verify_endpoint_exposure",
        "description": "Perform an active, non-invasive HTTP HEAD probe to verify if a discovered URL is genuinely exposed (200 OK) vs protected (403/404).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL to probe, e.g. 'https://target.com/.env'"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "get_remediation_playbook",
        "description": "Retrieve comprehensive remediation directives, OWASP mappings, and action steps for a vulnerability classification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Security finding category",
                    "enum": ["CONFIG_LEAK", "TOKEN_LEAK", "DATABASE_LEAK", "STORAGE_EXPOSURE", "API_DOCS", "INFRASTRUCTURE", "API_EXPOSURE"]
                }
            },
            "required": ["category"]
        }
    }
]

class MCPServer:
    """
    Standard JSON-RPC 2.0 Model Context Protocol Server.
    Provides execution of security tools and resource queries.
    """

    def __init__(self):
        self.search_client = OpenSearchClient()

    def get_tools(self) -> List[Dict[str, Any]]:
        """Return the list of declared MCP tools."""
        return MCP_TOOLS

    def handle_json_rpc(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes standard JSON-RPC 2.0 requests.
        Supported methods:
        - initialize
        - tools/list
        - tools/call
        - resources/list
        - ping
        """
        req_id = request_payload.get("id")
        jsonrpc = request_payload.get("jsonrpc", "2.0")
        method = request_payload.get("method")
        params = request_payload.get("params", {})

        if jsonrpc != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: jsonrpc must be '2.0'"}
            }

        try:
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "serverInfo": SERVER_INFO,
                        "capabilities": {
                            "tools": {"listChanged": False},
                            "resources": {"subscribe": False, "listChanged": False}
                        }
                    }
                }

            elif method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {}}

            elif method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": MCP_TOOLS}
                }

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                result_content, is_error = self.execute_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result_content, indent=2)}],
                        "isError": is_error
                    }
                }

            elif method == "resources/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "resources": [
                            {
                                "uri": "recon://scans/summary",
                                "name": "ReconFlow Scan Telemetry",
                                "mimeType": "application/json"
                            }
                        ]
                    }
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method '{method}' not found"}
                }

        except Exception as exc:
            logger.exception("Error executing MCP method %s: %s", method, str(exc))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Internal RPC error: {str(exc)}"}
            }

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Tuple[Any, bool]:
        """
        Dispatches execution of a named MCP tool.
        Returns: (result_data, is_error)
        """
        if name == "harvest_subdomains":
            target = arguments.get("target", "").strip().lower()
            max_results = arguments.get("max_results", 30)
            if not target:
                return {"error": "Missing required argument 'target'"}, True
            
            # Use Certificate Transparency (crt.sh)
            crt_hosts = self.search_client.search_crt_sh(target)
            
            # Also combine with search query
            dork_results, _ = self.search_client.search(f"site:{target} -www.{target}", engine="google")
            dork_hosts = []
            for r in dork_results:
                l = r.get("link", "")
                h = urlparse(l).netloc.lower()
                if h and h.endswith(target) and h != target and h != f"www.{target}":
                    dork_hosts.append(h)

            all_hosts = sorted(list(set(crt_hosts + dork_hosts)))[:max_results]
            return {
                "target": target,
                "source": "Certificate Transparency (crt.sh) + Multi-Engine OSINT",
                "subdomain_count": len(all_hosts),
                "subdomains": all_hosts
            }, False

        elif name == "search_threat_dorks":
            target = arguments.get("target", "").strip().lower()
            category = arguments.get("category", "general")
            
            dork_map = {
                "admin_gateways": f"site:{target} (inurl:admin OR inurl:login OR inurl:portal OR inurl:dashboard)",
                "config_leaks": f"site:{target} (filetype:env OR filetype:sql OR filetype:bak OR filetype:yaml)",
                "api_docs": f"site:{target} (inurl:swagger OR inurl:api-docs OR inurl:graphql OR inurl:redoc)",
                "credentials": f"site:github.com \"{target}\" (api_key OR token OR secret OR password)",
                "cloud_storage": f"site:s3.amazonaws.com \"{target}\" OR site:{target} \"s3.amazonaws.com\"",
                "general": f"site:{target}"
            }
            query = dork_map.get(category, f"site:{target}")
            results, err = self.search_client.search(query, engine="google")
            
            return {
                "target": target,
                "category": category,
                "query": query,
                "count": len(results),
                "results": results[:10],
                "error": err
            }, False

        elif name == "audit_cloud_storage":
            target = arguments.get("target", "").strip().lower()
            provider = arguments.get("provider", "aws_s3")
            
            if provider == "aws_s3":
                q = f"site:s3.amazonaws.com \"{target}\" OR site:{target} \"s3.amazonaws.com\""
            elif provider == "gcp_storage":
                q = f"site:storage.googleapis.com \"{target}\""
            else:
                q = f"site:blob.core.windows.net \"{target}\""

            results, err = self.search_client.search(q, engine="google")
            return {
                "target": target,
                "provider": provider,
                "query": q,
                "exposed_buckets": results[:10],
                "error": err
            }, False

        elif name == "verify_endpoint_exposure":
            url = arguments.get("url", "")
            if not url:
                return {"error": "Missing 'url' argument"}, True
            probe_result = verify_http_exposure(url)
            return probe_result, False

        elif name == "get_remediation_playbook":
            category = arguments.get("category", "INFRASTRUCTURE")
            playbook = get_remediation_for_category(category)
            return {
                "category": category,
                "playbook": playbook
            }, False

        else:
            return {"error": f"Unknown tool name: {name}"}, True

# Global instance for import
mcp_server = MCPServer()
