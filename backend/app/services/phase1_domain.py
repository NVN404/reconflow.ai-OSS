import re
import datetime
import logging
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from app.cache import get_cached_scan, set_cached_scan
from app.schemas import ScanResult, ScanSummary, AgentThought
from app.services.triage import compute_security_score, build_executive_summary, layout_graph, ai_triage_findings
from app.remediation import get_remediation_for_category
from app.services.phase2_external import Phase2ExternalScanner
from app.services.open_search_client import OpenSearchClient
from app.services.exposure_prober import verify_http_exposure
from app.services.mcp_agent import AutonomousMCPAgent

logger = logging.getLogger("reconflow.scanner")


def is_valid_config_leak(link: str, title: str, snippet: str) -> Tuple[bool, str]:
    """
    Returns (is_leak, leak_title).
    Strictly verifies that the URL or content points to a REAL sensitive file or directory listing.
    Standard web pages (careers, blog, marketing, docs, etc.) are NEVER leaks.
    """
    parsed = urlparse(link)
    path = parsed.path.lower()
    t_lower = title.lower()
    s_lower = snippet.lower()
    
    # 1. Reject normal web pages immediately
    normal_sections = [
        "/careers", "/jobs", "/blog", "/about", "/pricing", "/faq", "/help", 
        "/support", "/contact", "/terms", "/privacy", "/features", "/integrations", 
        "/customers", "/solutions", "/resources", "/press", "/articles", "/status",
        "/forum", "/community", "/docs", "/documentation", "/products", "/case-studies",
        "/amazon-filters", "/inline-videos", "/shopping-results", "/google-domains",
        "/apple-languages", "/broaden-searches"
    ]
    if any(path == sec or path.startswith(sec + "/") or path.endswith(sec) for sec in normal_sections):
        return False, ""
        
    # 2. Open Directory Listing
    if "index of /" in t_lower or "index of /" in s_lower or "parent directory" in s_lower:
        return True, "Open Directory Listing Exposing Server Files"
        
    # 3. Environment configuration files
    if "/.env" in path or path.endswith(".env") or path.endswith(".env.local") or path.endswith(".env.production"):
        return True, "Exposed Environment Configuration (.env) File"
        
    # 4. Database dumps & SQL files
    if path.endswith(".sql") or path.endswith(".sql.gz") or path.endswith(".dump"):
        return True, "Exposed Raw Database SQL Dump"
        
    # 5. Backup archives & swap files
    if path.endswith((".bak", ".old", ".swp", ".backup", ".tar.gz", ".zip")) and any(k in path for k in ["db", "dump", "backup", "data", "conf"]):
        return True, "Exposed Source Code or Database Backup Archive"
        
    # 6. Server telemetry / phpinfo
    if "phpinfo.php" in path or "/server-status" in path:
        return True, "Exposed Server Runtime Telemetry / PHPInfo"
        
    # 7. Git repository exposure
    if "/.git/" in path or path.endswith("/.git"):
        return True, "Exposed Git Version Control Metadata (.git/)"
        
    return False, ""


def is_valid_token_leak(link: str, snippet: str) -> Tuple[bool, str, str]:
    """
    Checks if snippet contains real high-entropy cloud token signatures.
    """
    signatures = [
        ("Google API Key", r"AIzaSy[0-9A-Za-z-_]{33}"),
        ("Stripe Live Secret", r"sk_live_[0-9a-zA-Z]{24}"),
        ("GitHub Personal Access Token", r"ghp_[0-9a-zA-Z]{36}"),
        ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}")
    ]
    for token_type, pattern in signatures:
        match = re.search(pattern, snippet)
        if match:
            return True, token_type, match.group(0)
    return False, "", ""


def is_valid_document_leak(link: str, title: str, snippet: str) -> Tuple[bool, str]:
    """
    Checks for sensitive corporate documents (PDF, Excel, Word).
    """
    parsed = urlparse(link)
    path = parsed.path.lower()
    t_lower = title.lower()
    s_lower = snippet.lower()
    
    # Must be document extension
    if not path.endswith((".pdf", ".xlsx", ".xls", ".docx", ".doc")):
        return False, ""
        
    # Must contain confidentiality markings
    confidential_markers = [
        "confidential", "internal use only", "proprietary", "not for public distribution",
        "strictly private", "nda required", "privileged & confidential"
    ]
    if any(m in t_lower or m in s_lower for m in confidential_markers):
        if not any(x in path for x in ["/terms", "/privacy", "/press-release", "/whitepaper"]):
            doc_type = path.split(".")[-1].upper()
            return True, f"Exposed Confidential Corporate Document ({doc_type})"
            
    return False, ""


def is_valid_auth_gateway(link: str) -> Tuple[bool, str]:
    """
    Checks if URL points to an administrative or login portal.
    """
    parsed = urlparse(link)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    
    auth_subdomains = ("admin.", "login.", "auth.", "portal.", "dashboard.", "sso.", "id.", "accounts.")
    if host.startswith(auth_subdomains):
        return True, "Dedicated Authentication / Admin Subdomain"
        
    auth_paths = ["/login", "/admin", "/auth", "/dashboard", "/portal", "/signin", "/sso", "/user/login", "/admin/login"]
    if any(path == p or path.startswith(p + "/") for p in auth_paths):
        if not any(x in path for x in ["/blog", "/docs", "/article", "/posts", "/news", "/careers"]):
            return True, "Public Authentication Gateway"
            
    return False, ""


class Phase1DomainScanner:
    def __init__(self):
        self.search_client = OpenSearchClient()
        self.mcp_agent = AutonomousMCPAgent()

    def execute_search_query(self, query: str, engine: str = "google") -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Execute a search query using the open-source search client."""
        return self.search_client.search(query, engine=engine)

    def scan(
        self,
        target: str,
        use_cache: bool = True,
        enable_phase2: bool = False,
        custom_dorks: Optional[List[str]] = None,
        enabled_vectors: Optional[Dict[str, bool]] = None,
        protocol: str = "rest"
    ) -> ScanResult:
        clean_target = target.strip().lower()
        clean_target = re.sub(r"^https?://", "", clean_target).rstrip("/")
        brand_name = clean_target.split(".")[0]
        
        # Check cache if enabled
        if use_cache:
            cached = get_cached_scan(clean_target)
            if cached:
                return ScanResult(
                    summary=ScanSummary(**cached["summary"]),
                    executive_summary=cached.get("executive_summary", ""),
                    nodes=cached.get("nodes", []),
                    edges=cached.get("edges", []),
                    thoughts=[AgentThought(**t) for t in cached.get("thoughts", [])]
                )

        thoughts: List[AgentThought] = []
        now = datetime.datetime.now().strftime("%H:%M:%S")
        protocol_mode = (protocol or "rest").lower()
        if protocol_mode not in ["rest", "mcp", "both"]:
            protocol_mode = "rest"

        thoughts.append(AgentThought(
            timestamp=now,
            stage="INITIALIZATION",
            message=f"ReconFlow Engine armed for: {clean_target} [Protocol: {protocol_mode.upper()}] (Phase 2: {'ON' if enable_phase2 else 'OFF'})",
            status="info"
        ))

        proxy_info = self.search_client.get_proxy_status()
        if proxy_info.get("enabled"):
            thoughts.append(AgentThought(
                timestamp=now,
                stage="PROXY_SHIELD",
                message=f"Proxy Shield Active: {proxy_info['active_proxies']} rotating nodes in pool",
                status="success"
            ))

        subdomains: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        external_findings: List[Dict[str, Any]] = []
        discovered_hosts = set()
        queries_used = 0

        def register_host(host_str: str, link_url: str, snip: str, dork: str, eng: str):
            if host_str and host_str.endswith(clean_target) and host_str != f"www.{clean_target}" and host_str != clean_target:
                if host_str not in discovered_hosts:
                    discovered_hosts.add(host_str)
                    subdomains.append({
                        "host": host_str,
                        "url": link_url,
                        "snippet": snip,
                        "dork": dork,
                        "engine": eng
                    })

        def inspect_result_for_vulnerabilities(res: Dict[str, Any], dork_str: str, eng: str):
            link = res.get("link", "")
            if not link:
                return
            title = res.get("title", "")
            snip = res.get("snippet", "")
            host = urlparse(link).netloc.lower()

            if any(f.get("url") == link for f in findings):
                return

            parsed_url = urlparse(link)
            query_str = unquote(parsed_url.query.lower())
            path_str = unquote(parsed_url.path.lower())

            # 1. SQL indicators in indexed query string (Passive observation - demoted to LOW / INFO)
            sql_indicators = ["union select", "union%20select", "select @@", "select%20@@", "substring((", "waitfor delay", "' or '", "admin'--"]
            if any(k in query_str for k in sql_indicators):
                playbook = get_remediation_for_category("DATABASE_LEAK")
                findings.append({
                    "title": "Indexed Query Parameter Containing SQL Query Syntax",
                    "category": "DATABASE_LEAK",
                    "severity": "LOW",
                    "section": "INFO",
                    "host": host,
                    "url": link,
                    "snippet": snip or f"Search engine indexed parameter containing SQL query syntax at {link}.",
                    "dork": dork_str,
                    "surface": "Search Engine Index Cache",
                    "engine": eng,
                    "what_is_the_bug": f"Search engine indexed a URL with SQL query syntax in the query parameter at {link}.",
                    "why_it_is_a_bug": "Indexed query strings containing database syntax can reveal unparameterized endpoints or public debug query logs. Note: Passive search observation only; active database exploitation is unverified.",
                    "attack_vector": "Adversaries discover search-indexed query strings to probe for input sanitization weaknesses.",
                    "how_to_fix": "Enforce parameterized database queries (prepared statements) and sanitize input arguments.",
                    "remediation": "Audit the endpoint parameter and ensure all database queries use prepared statements.",
                    "owasp_tag": "OWASP A03:2021 — Injection",
                    "cwe_id": "CWE-89: SQL Injection",
                    "cvss_score": "3.1 (Low / Informational)",
                    "remediation_steps": playbook.get("remediation_steps", [])
                })

            # 2. Reflected script tags in query string (Passive observation - demoted to LOW / INFO)
            elif any(k in query_str for k in ["<script", "alert(", "javascript:", "<svg", "<img src=x"]):
                playbook = get_remediation_for_category("API_EXPOSURE")
                findings.append({
                    "title": "Indexed Query Parameter Containing Script Syntax",
                    "category": "API_EXPOSURE",
                    "severity": "LOW",
                    "section": "INFO",
                    "host": host,
                    "url": link,
                    "snippet": snip or "Script syntax detected in indexed URL parameter.",
                    "dork": dork_str,
                    "surface": "Search Engine Index Cache",
                    "engine": eng,
                    "what_is_the_bug": f"Search engine cached an endpoint reflecting script tags in query parameters at {link}.",
                    "why_it_is_a_bug": "Unsanitized user input reflected in HTTP responses may allow arbitrary script execution if reflection is live and unencoded.",
                    "attack_vector": "Adversaries craft malicious links containing script payloads targeting authenticated victim sessions.",
                    "how_to_fix": "Enforce context-aware HTML entity encoding and configure strict Content Security Policy (CSP).",
                    "remediation": "Deploy Content Security Policy (CSP) headers and encode dynamic query string outputs.",
                    "owasp_tag": "OWASP A03:2021 — Injection / XSS",
                    "cwe_id": "CWE-79: Cross-site Scripting",
                    "cvss_score": "3.1 (Low / Informational)",
                    "remediation_steps": playbook.get("remediation_steps", [])
                })

            # 3. Directory Traversal indicators
            elif any(k in query_str or k in path_str for k in ["../", "..%2f", "/etc/passwd", "win.ini"]):
                playbook = get_remediation_for_category("STORAGE_EXPOSURE")
                findings.append({
                    "title": "Directory Traversal Parameter Syntax Detected",
                    "category": "STORAGE_EXPOSURE",
                    "severity": "MEDIUM",
                    "section": "VULNERABILITY",
                    "host": host,
                    "url": link,
                    "snippet": snip or "Directory traversal parameter syntax detected in search index.",
                    "dork": dork_str,
                    "surface": "Search Engine Index Cache",
                    "engine": eng,
                    "what_is_the_bug": f"Indexed path indicators show potential local file inclusion or traversal syntax at {link}.",
                    "why_it_is_a_bug": "Improper file path sanitization allows adversaries to retrieve unauthorized files from the filesystem.",
                    "attack_vector": "Adversary manipulates path parameters to read server configuration files.",
                    "how_to_fix": "Validate and whitelist filenames; avoid using raw user inputs in file access APIs.",
                    "remediation": "Restrict filesystem operations to a chrooted directory and sanitize all path inputs.",
                    "owasp_tag": "OWASP A01:2021 — Broken Access Control",
                    "cwe_id": "CWE-22: Path Traversal",
                    "cvss_score": "6.3 (Medium)",
                    "remediation_steps": playbook.get("remediation_steps", [])
                })

        # --- STEP 1: CERTIFICATE TRANSPARENCY SUBDOMAIN HARVESTING (Zero Blocks, 100% Reliable) ---
        thoughts.append(AgentThought(
            timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
            stage="CERT_TRANSPARENCY",
            message=f"Querying Certificate Transparency logs (crt.sh) for '{clean_target}'...",
            status="info"
        ))
        crt_subs = self.search_client.search_crt_sh(clean_target)
        for s in crt_subs:
            register_host(s, f"https://{s}", "Discovered via Certificate Transparency logs (crt.sh).", "crt.sh", "crt.sh")

        thoughts.append(AgentThought(
            timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
            stage="CERT_TRANSPARENCY_DONE",
            message=f"Certificate Transparency enumerated {len(crt_subs)} verified subdomains.",
            status="success"
        ))

        # --- STEP 2: CONCURRENT MULTI-ENGINE PASSES ---
        # Run independent queries concurrently via ThreadPoolExecutor to prevent blocking
        search_passes = [
            ("google", f"site:{clean_target} -www.{clean_target}", "PASS_1_1"),
            ("duckduckgo", f"site:{clean_target} -www.{clean_target}", "PASS_1_1B"),
            ("google", f"site:{clean_target} (inurl:admin OR inurl:login OR inurl:portal OR inurl:auth OR inurl:docs OR inurl:api OR inurl:dashboard)", "PASS_1_2"),
            ("google", f"site:{clean_target}", "PASS_1_2B"),
            ("google", f"site:{clean_target} (filetype:env OR filetype:sql OR filetype:yaml OR filetype:log OR filetype:bak OR intitle:\"index of /\")", "PASS_1_3"),
            ("google", f"site:{clean_target} (\"AIzaSy\" OR \"sk_live_\" OR \"ghp_\" OR \"AKIA\")", "PASS_1_4"),
            ("google", f"site:{clean_target} (filetype:pdf OR filetype:xlsx OR filetype:docx) (\"CONFIDENTIAL\" OR \"INTERNAL USE ONLY\" OR \"PROPRIETARY\")", "PASS_1_5"),
        ]

        def run_pass(engine: str, query: str, stage_tag: str):
            res, err = self.execute_search_query(query, engine=engine)
            return stage_tag, query, engine, res or [], err

        thoughts.append(AgentThought(
            timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
            stage="CONCURRENT_DORKS",
            message=f"Executing {len(search_passes)} concurrent search passes across Google & DuckDuckGo...",
            status="info"
        ))

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_pass = {executor.submit(run_pass, p[0], p[1], p[2]): p for p in search_passes}
            for future in as_completed(future_to_pass):
                stage_tag, query, engine, results, err = future.result()
                if results:
                    queries_used += 1

                # Process results based on stage
                if stage_tag in ["PASS_1_1", "PASS_1_1B"]:
                    for res in results:
                        link = res.get("link", "")
                        host = urlparse(link).netloc.lower()
                        register_host(host, link, res.get("snippet", "Active subdomain asset."), query, engine)
                        inspect_result_for_vulnerabilities(res, query, engine)

                elif stage_tag == "PASS_1_2":
                    for res in results:
                        link = res.get("link", "")
                        host = urlparse(link).netloc.lower()
                        register_host(host, link, res.get("snippet", "Discovered host cluster."), query, engine)
                        if host == clean_target or host.endswith("." + clean_target):
                            is_auth, auth_title = is_valid_auth_gateway(link)
                            if is_auth:
                                playbook = get_remediation_for_category("INFRASTRUCTURE")
                                findings.append({
                                    "title": auth_title,
                                    "category": "INFRASTRUCTURE",
                                    "severity": "LOW",
                                    "host": host,
                                    "url": link,
                                    "snippet": res.get("snippet", "Exposed public login / access portal."),
                                    "dork": query,
                                    "surface": "Authentication Gateway",
                                    "engine": engine,
                                    "what_is_the_bug": f"Publicly accessible authentication or administrative gateway at {link}.",
                                    "why_it_is_a_bug": playbook.get("why_it_is_a_bug"),
                                    "attack_vector": playbook.get("attack_vector"),
                                    "how_to_fix": playbook.get("how_to_fix"),
                                    "remediation": playbook.get("default_directive"),
                                    "owasp_tag": playbook.get("owasp_tag"),
                                    "cwe_id": playbook.get("cwe_id"),
                                    "cvss_score": playbook.get("cvss_score")
                                })

                elif stage_tag == "PASS_1_2B":
                    for res in results[:5]:
                        link = res.get("link", "")
                        host = urlparse(link).netloc.lower()
                        register_host(host, link, res.get("snippet", "Discovered host cluster."), query, engine)

                elif stage_tag == "PASS_1_3":
                    for res in results:
                        link = res.get("link", "")
                        host = urlparse(link).netloc.lower()
                        if not (host == clean_target or host.endswith("." + clean_target)):
                            continue
                        snippet = res.get("snippet", "")
                        title = res.get("title", "")
                        is_leak, leak_title = is_valid_config_leak(link, title, snippet)
                        if not is_leak:
                            continue

                        # Active HTTP Verification Probe (Eliminates soft 404 false positives)
                        probe = verify_http_exposure(link, timeout=2.5)
                        if probe.get("is_false_positive") and probe.get("status_code") == 200:
                            # Discard soft 404 SPA fallback
                            continue

                        playbook = get_remediation_for_category("CONFIG_LEAK")
                        if probe.get("verified"):
                            severity = "CRITICAL"
                            section = "VULNERABILITY"
                            ver_title = f"VERIFIED ACTIVE LEAK: {leak_title}"
                            ver_snippet = f"Confirmed active exposure (HTTP 200, {probe.get('content_type')}). {snippet}"
                        elif probe.get("status_code") in (401, 403):
                            severity = "LOW"
                            section = "INFO"
                            ver_title = f"Protected Config Asset: {leak_title} (HTTP {probe.get('status_code')})"
                            ver_snippet = f"Server access restricted (HTTP {probe.get('status_code')}). {snippet}"
                        else:
                            severity = "MEDIUM"
                            section = "INFO"
                            ver_title = leak_title
                            ver_snippet = snippet or "Indexed configuration path observed."

                        findings.append({
                            "title": ver_title,
                            "category": "CONFIG_LEAK",
                            "severity": severity,
                            "section": section,
                            "host": host,
                            "url": link,
                            "snippet": ver_snippet,
                            "dork": query,
                            "surface": "Web Server Root",
                            "engine": engine,
                            "what_is_the_bug": f"Indexed sensitive configuration path at {link} (Probe: {probe.get('reason')}).",
                            "why_it_is_a_bug": playbook.get("why_it_is_a_bug"),
                            "attack_vector": playbook.get("attack_vector"),
                            "how_to_fix": playbook.get("how_to_fix"),
                            "remediation": playbook.get("default_directive"),
                            "owasp_tag": playbook.get("owasp_tag"),
                            "cwe_id": playbook.get("cwe_id"),
                            "cvss_score": playbook.get("cvss_score")
                        })

                elif stage_tag == "PASS_1_4":
                    for res in results:
                        link = res.get("link", "")
                        host = urlparse(link).netloc.lower()
                        if not (host == clean_target or host.endswith("." + clean_target)):
                            continue
                        snip = res.get("snippet", "")
                        is_token, token_type, matched_sig = is_valid_token_leak(link, snip)
                        if is_token:
                            playbook = get_remediation_for_category("TOKEN_LEAK")
                            findings.append({
                                "title": f"Exposed Cloud Secret Signature ({token_type})",
                                "category": "TOKEN_LEAK",
                                "severity": "CRITICAL",
                                "section": "VULNERABILITY",
                                "host": host,
                                "url": link,
                                "snippet": snip or f"Hardcoded {token_type} signature detected: {matched_sig}",
                                "dork": query,
                                "surface": "Web Client Bundle / Source",
                                "engine": engine,
                                "what_is_the_bug": f"High-entropy {token_type} signature detected at {link}.",
                                "why_it_is_a_bug": playbook.get("why_it_is_a_bug"),
                                "attack_vector": playbook.get("attack_vector"),
                                "how_to_fix": playbook.get("how_to_fix"),
                                "remediation": playbook.get("default_directive"),
                                "owasp_tag": playbook.get("owasp_tag"),
                                "cwe_id": playbook.get("cwe_id"),
                                "cvss_score": playbook.get("cvss_score")
                            })

                elif stage_tag == "PASS_1_5":
                    for res in results:
                        link = res.get("link", "")
                        host = urlparse(link).netloc.lower()
                        if not (host == clean_target or host.endswith("." + clean_target)):
                            continue
                        snip = res.get("snippet", "")
                        title = res.get("title", "")
                        is_doc, doc_title = is_valid_document_leak(link, title, snip)
                        if is_doc:
                            playbook = get_remediation_for_category("DOCUMENT_LEAK")
                            findings.append({
                                "title": doc_title,
                                "category": "DOCUMENT_LEAK",
                                "severity": "HIGH",
                                "section": "VULNERABILITY",
                                "host": host,
                                "url": link,
                                "snippet": snip or "Internal corporate document exposed to public crawlers.",
                                "dork": query,
                                "surface": "Internal Corporate Document",
                                "engine": engine,
                                "what_is_the_bug": f"Internal document with confidentiality markings at {link}.",
                                "why_it_is_a_bug": playbook.get("why_it_is_a_bug"),
                                "attack_vector": playbook.get("attack_vector"),
                                "how_to_fix": playbook.get("how_to_fix"),
                                "remediation": playbook.get("default_directive"),
                                "owasp_tag": playbook.get("owasp_tag"),
                                "cwe_id": playbook.get("cwe_id"),
                                "cvss_score": playbook.get("cvss_score")
                            })

        # --- STEP 3: PROTOCOL BRANCHING (REAL EXECUTION BRANCH) ---
        if protocol_mode in ["mcp", "both"]:
            thoughts.append(AgentThought(
                timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
                stage="MCP_AGENT_DISPATCH",
                message=f"Dispatching autonomous MCP Agent tool pipeline for target: '{clean_target}'",
                status="info"
            ))
            # Execute cloud storage audit tool via MCP Agent
            cloud_tool_resp = self.mcp_agent.execute_agent_chat(
                target=clean_target,
                user_message="Audit AWS S3 buckets and cloud storage exposures"
            )
            if cloud_tool_resp.get("findings"):
                for mcp_f in cloud_tool_resp["findings"]:
                    findings.append(mcp_f.get("data", {}))

            if cloud_tool_resp.get("thought"):
                thoughts.append(AgentThought(
                    timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
                    stage="MCP_TOOL_EXEC",
                    message=cloud_tool_resp["thought"],
                    status="success"
                ))

        # --- STEP 4: PHASE 2 EXTERNAL EXPANSION ---
        if enable_phase2:
            p2_scanner = Phase2ExternalScanner(execute_search_fn=self.execute_search_query)
            p2_findings, p2_thoughts, p2_queries = p2_scanner.run_phase2_sweep(
                clean_target=clean_target,
                brand_name=brand_name,
                custom_dorks=custom_dorks,
                enabled_vectors=enabled_vectors
            )
            external_findings.extend(p2_findings)
            thoughts.extend(p2_thoughts)
            queries_used += p2_queries

        # --- STEP 5: AI TRIAGE LAYER ---
        if protocol_mode != "rest":
            thoughts.append(AgentThought(
                timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
                stage="AI_TRIAGE_INIT",
                message=f"Triage evaluating {len(findings) + len(external_findings)} candidate findings...",
                status="info"
            ))
            vetted_findings, int_discarded = ai_triage_findings(findings, clean_target, brand_name)
            vetted_external, ext_discarded = ai_triage_findings(external_findings, clean_target, brand_name)
            total_discarded = len(int_discarded) + len(ext_discarded)
            findings = vetted_findings
            external_findings = vetted_external
        else:
            total_discarded = 0

        # Assemble graph nodes and edges
        nodes, edges = layout_graph(clean_target, subdomains, findings, external_findings)

        critical_count = sum(1 for f in findings + external_findings if f.get("severity") == "CRITICAL" and f.get("category") != "VULN_STATUS_CLEAN")
        high_count = sum(1 for f in findings + external_findings if f.get("severity") == "HIGH")
        medium_count = sum(1 for f in findings + external_findings if f.get("severity") == "MEDIUM")
        low_count = len(subdomains) + sum(1 for f in findings + external_findings if f.get("severity") == "LOW")
        info_count = 1 + sum(1 for f in findings + external_findings if f.get("severity") == "INFO")

        vulnerability_count = sum(1 for f in findings + external_findings if f.get("section") == "VULNERABILITY" and f.get("category") != "VULN_STATUS_CLEAN")
        info_assets_count = len(nodes) - vulnerability_count

        score, grade = compute_security_score(critical_count, high_count, medium_count, low_count)
        exec_summary = build_executive_summary(clean_target, len(nodes), critical_count, high_count, medium_count, score, grade)

        # Set protocol_used truthfully based on mode
        actual_protocol = "direct_rest" if protocol_mode == "rest" else "mcp_agent" if protocol_mode == "mcp" else "dual_hybrid"

        summary = ScanSummary(
            target=clean_target,
            total_nodes=len(nodes),
            critical_risks=critical_count,
            high_risks=high_count,
            medium_risks=medium_count,
            low_risks=low_count,
            info=info_count,
            info_assets_count=info_assets_count,
            vulnerability_count=vulnerability_count,
            external_threat_count=len(external_findings),
            ai_discarded_noise_count=total_discarded,
            security_score=score,
            security_grade=grade,
            search_queries_used=queries_used,
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            protocol_used=actual_protocol
        )

        result = ScanResult(
            summary=summary,
            executive_summary=exec_summary,
            nodes=nodes,
            edges=edges,
            thoughts=thoughts
        )

        # Persist to disk cache
        if use_cache:
            set_cached_scan(clean_target, result.model_dump())

        return result
