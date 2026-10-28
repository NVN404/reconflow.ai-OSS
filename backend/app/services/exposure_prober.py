"""
Exposure Prober: Active Non-Invasive Verification Service.
Provides lightweight HTTP HEAD and streamed GET probes to verify whether
search-indexed sensitive assets (.env, .git, backup archives, phpinfo)
are genuinely exposed with active 200 OK responses and real payload contents,
or if they are 403 Forbidden / 404 Not Found / generic SPA HTML error fallbacks.
"""

import re
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests

logger = logging.getLogger("reconflow.prober")

PROBE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconFlow-EASM-Audit/2.0",
    "Accept": "*/*",
    "Connection": "close"
}

def verify_http_exposure(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Sends a non-invasive HTTP probe (with payload inspection on 200 OK)
    to check if an indexed sensitive asset is genuinely accessible.
    """
    if not url or not url.startswith(("http://", "https://")):
        return {
            "verified": False,
            "status_code": 0,
            "reason": "Invalid URL scheme",
            "content_type": "",
            "is_false_positive": True,
            "details": "URL must start with http:// or https://"
        }

    try:
        with requests.Session() as session:
            session.headers.update(PROBE_HEADERS)

            # Perform a byte-limited streamed GET probe
            # Reading up to 2048 bytes allows inspecting headers AND body sample
            resp = session.get(url, timeout=timeout, allow_redirects=False, stream=True)
            status_code = resp.status_code
            content_type = resp.headers.get("Content-Type", "").lower()
            
            # Read first 2KB sample safely
            sample = resp.raw.read(2048).decode("utf-8", errors="ignore")
            resp.close()

            url_path = urlparse(url).path.lower()
            sample_lower = sample.lower()

            # Evaluation logic
            if status_code == 200:
                # 1. Soft-404 / Single Page Application router check:
                # SPAs (Next.js, React, Vue, Angular, NGINX try_files) return 200 OK with an HTML page for non-existent assets.
                is_html_content = "text/html" in content_type or "<!doctype html" in sample_lower or "<html" in sample_lower
                has_spa_or_error_markers = any(
                    sig in sample_lower for sig in [
                        "<!doctype html", "<html", "<body", "page not found", "404 not found",
                        "cannot find", "not found", "doesn't exist", "react", "next-route-announcer",
                        "div id=\"root\"", "div id=\"__next\""
                    ]
                )

                is_file_asset = any(url_path.endswith(ext) for ext in [
                    ".env", ".env.local", ".env.production", ".sql", ".bak", ".old",
                    ".swp", ".log", ".yaml", ".yml", ".json", ".key", ".pem", ".git/config"
                ])

                if is_file_asset and (is_html_content or has_spa_or_error_markers):
                    return {
                        "verified": False,
                        "status_code": 200,
                        "reason": "Soft 404 / SPA Router Fallback",
                        "content_type": content_type,
                        "is_false_positive": True,
                        "details": f"Server responded 200 OK but returned an HTML document/SPA page rather than raw {url_path.split('/')[-1]} data."
                    }

                # 2. Strict payload validation for .env files
                if "/.env" in url_path or url_path.endswith(".env"):
                    # Real .env file MUST contain KEY=VALUE definitions or shell comments
                    has_env_assignments = bool(re.search(r"^[A-Za-z0-9_]{2,}\s*=", sample, flags=re.MULTILINE))
                    has_env_comments = "#" in sample
                    if not (has_env_assignments or has_env_comments) or is_html_content:
                        return {
                            "verified": False,
                            "status_code": 200,
                            "reason": "Non-Env Content Returned",
                            "content_type": content_type,
                            "is_false_positive": True,
                            "details": "Server returned 200 OK but content does not match environment variable syntax."
                        }

                # 3. Strict payload validation for .sql files
                if url_path.endswith(".sql"):
                    has_sql_markers = any(k in sample_lower for k in [
                        "create table", "insert into", "select ", "drop table", "database", "-- ", "/*"
                    ])
                    if not has_sql_markers or is_html_content:
                        return {
                            "verified": False,
                            "status_code": 200,
                            "reason": "Non-SQL Content Returned",
                            "content_type": content_type,
                            "is_false_positive": True,
                            "details": "Server returned 200 OK but content does not contain valid SQL statements."
                        }

                return {
                    "verified": True,
                    "status_code": 200,
                    "reason": "Resource Accessible (200 OK)",
                    "content_type": content_type,
                    "is_false_positive": False,
                    "details": f"Active exposure verified with HTTP 200 OK (Content-Type: {content_type})."
                }

            elif status_code in (401, 403):
                return {
                    "verified": False,
                    "status_code": status_code,
                    "reason": f"Access Restricted ({status_code})",
                    "content_type": content_type,
                    "is_false_positive": False,
                    "details": f"Resource exists or is blocked by access controls (HTTP {status_code}). Not publicly readable."
                }
            elif status_code in (301, 302, 307, 308):
                return {
                    "verified": False,
                    "status_code": status_code,
                    "reason": f"Redirect ({status_code})",
                    "content_type": content_type,
                    "is_false_positive": True,
                    "details": f"Endpoint redirected (HTTP {status_code}) towards login or canonical URL."
                }
            elif status_code == 404:
                return {
                    "verified": False,
                    "status_code": 404,
                    "reason": "Not Found (404)",
                    "content_type": content_type,
                    "is_false_positive": True,
                    "details": "Asset has been removed or does not exist at this path."
                }
            else:
                return {
                    "verified": False,
                    "status_code": status_code,
                    "reason": f"HTTP {status_code}",
                    "content_type": content_type,
                    "is_false_positive": False,
                    "details": f"Server returned status {status_code}."
                }

    except Exception as exc:
        return {
            "verified": False,
            "status_code": 0,
            "reason": "Connection Failed",
            "content_type": "",
            "is_false_positive": True,
            "details": f"Probing request failed: {str(exc)}"
        }
