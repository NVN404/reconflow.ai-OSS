"use client";

import React, { useState, useMemo, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Sparkles,
  Lock,
  ShieldCheck,
  LogOut,
  ArrowLeft,
  Download,
  Zap,
  CheckCircle2,
  X,
  AlertCircle,
  Network,
  Bot,
} from "lucide-react";

import { SearchBar } from "@/components/SearchBar";
import { SummaryCards } from "@/components/SummaryCards";
import { GraphCanvas } from "@/components/GraphCanvas";
import { FindingDrawer } from "@/components/FindingDrawer";
import { ThoughtStream } from "@/components/ThoughtStream";

import { ThemeToggle } from "@/components/ThemeToggle";
import { MCPChatPanel, ChatMessage } from "@/components/MCPChatPanel";
import { MCPFindingsSidebar } from "@/components/MCPFindingsSidebar";

import { getLayoutedElements } from "@/lib/layout";
import { ScanResult, GraphNode, AgentThought } from "@/lib/types";
import { generateAuditDossier } from "@/lib/dossier";

const initialScanResult: ScanResult = {
  summary: {
    target: "Standing By",
    total_nodes: 0,
    critical_risks: 0,
    high_risks: 0,
    medium_risks: 0,
    low_risks: 0,
    info: 0,
    security_score: 100,
    security_grade: "A",
    search_queries_used: 0,
    generated_at: "2026-10-05T00:00:00Z",
  },
  executive_summary:
    "ReconFlow AI Standing By. Enter any target perimeter (e.g. vulnweb.com) to initiate autonomous external reconnaissance.",
  nodes: [],
  edges: [],
  thoughts: [],
};

function ReconWorkspaceContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const initialTarget = searchParams.get("target") || "vulnweb.com";

  const [scanResult, setScanResult] = useState<ScanResult>(initialScanResult);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>("ALL");
  const [layoutDirection, setLayoutDirection] = useState<"TB" | "LR">("TB");
  const [isScanning, setIsScanning] = useState<boolean>(false);

  // Recon Protocol & Workspace View State
  const [selectedProtocol, setSelectedProtocol] = useState<"rest" | "mcp" | "both">("rest");
  const [executedProtocol, setExecutedProtocol] = useState<"rest" | "mcp" | "both" | null>(null);
  const displayMode = selectedProtocol;
  const [bothActiveView, setBothActiveView] = useState<"graph" | "chat">("graph");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);

  // 100% Free & Open-Source: Unlimited Scans with zero payment gatekeeping
  const [thoughts, setThoughts] = useState<AgentThought[]>([
    {
      timestamp: "READY",
      stage: "ARMED",
      message: "ReconFlow AI Autonomous Recon Agent initialized. Standing by for target perimeter.",
      status: "info",
    },
    {
      timestamp: "READY",
      stage: "READY",
      message: "Autonomous passive external reconnaissance engine armed (100% Open Source).",
      status: "success",
    },
  ]);

  // Compute Dagre Layout for React Flow
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(() => {
    if (!scanResult || scanResult.nodes.length === 0) {
      return { nodes: [], edges: [] };
    }

    let filteredNodes = scanResult.nodes;
    if (activeFilter === "VULNERABILITIES") {
      filteredNodes = scanResult.nodes.filter(
        (n) => n.data.severity === "CRITICAL" || n.data.severity === "HIGH" || n.data.severity === "MEDIUM"
      );
    } else if (activeFilter === "CRITICAL") {
      filteredNodes = scanResult.nodes.filter((n) => n.data.severity === "CRITICAL");
    } else if (activeFilter === "HIGH") {
      filteredNodes = scanResult.nodes.filter((n) => n.data.severity === "HIGH");
    } else if (activeFilter === "MEDIUM") {
      filteredNodes = scanResult.nodes.filter((n) => n.data.severity === "MEDIUM");
    } else if (activeFilter === "ASSETS" || activeFilter === "LOW") {
      filteredNodes = scanResult.nodes.filter(
        (n) => n.type === "rootNode" || n.type === "subdomainNode"
      );
    } else if (activeFilter === "RADAR" || activeFilter === "THREAT_RADAR") {
      filteredNodes = scanResult.nodes.filter(
        (n) =>
          n.data.surface === "Threat Radar" ||
          n.type === "externalNode"
      );
    }

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = scanResult.edges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    return getLayoutedElements(
      filteredNodes as unknown as GraphNode[],
      filteredEdges,
      layoutDirection
    );
  }, [scanResult, activeFilter, layoutDirection]);

  // Actual API dispatch to backend
  // ─── Build MCP chat messages from scan results ──────────────────────────
  const buildChatMessagesFromScan = (data: ScanResult, domain: string) => {
    const now = new Date().toLocaleTimeString("en-GB");
    const messages: ChatMessage[] = [];

    // 1. Scan initiation message
    messages.push({
      id: `scan-init-${Date.now()}`,
      role: "agent",
      content: `Deploying open-source recon agents for target: ${domain}...`,
      timestamp: now,
      thoughts: data.thoughts?.slice(0, 5),
    });

    // 2. Executive summary + score card
    messages.push({
      id: `scan-summary-${Date.now()}`,
      role: "agent",
      content: data.executive_summary || `Scan complete for ${domain}. Here are the results:`,
      timestamp: now,
      scanSummary: {
        target: data.summary.target,
        securityScore: data.summary.security_score,
        securityGrade: data.summary.security_grade,
        criticalCount: data.summary.critical_risks,
        highCount: data.summary.high_risks,
        mediumCount: data.summary.medium_risks,
        lowCount: data.summary.low_risks,
        infoCount: data.summary.info,
      },
    });

    // 3. Critical & High findings as expandable cards
    const criticalFindings = data.nodes.filter(
      (n) => n.data.severity === "CRITICAL" || n.data.severity === "HIGH"
    );
    if (criticalFindings.length > 0) {
      messages.push({
        id: `scan-critical-${Date.now()}`,
        role: "agent",
        content: `🚨 Found ${criticalFindings.length} critical/high severity finding${criticalFindings.length > 1 ? "s" : ""} that require immediate attention:`,
        timestamp: now,
        findings: criticalFindings,
      });
    }

    // 4. Medium findings
    const mediumFindings = data.nodes.filter((n) => n.data.severity === "MEDIUM");
    if (mediumFindings.length > 0) {
      messages.push({
        id: `scan-medium-${Date.now()}`,
        role: "agent",
        content: `⚠️ ${mediumFindings.length} medium severity finding${mediumFindings.length > 1 ? "s" : ""} detected:`,
        timestamp: now,
        findings: mediumFindings,
      });
    }

    // 5. Clean / Info summary
    const cleanFindings = data.nodes.filter(
      (n) => n.data.category === "VULN_STATUS_CLEAN" || n.data.severity === "INFO" || n.data.severity === "LOW"
    );
    if (cleanFindings.length > 0) {
      messages.push({
        id: `scan-info-${Date.now()}`,
        role: "agent",
        content: `✅ ${cleanFindings.length} info/clean perimeter asset${cleanFindings.length > 1 ? "s" : ""} identified. These are low/no risk but documented for completeness.`,
        timestamp: now,
        findings: cleanFindings.slice(0, 6), // Limit to 6 to avoid clutter
      });
    }

    // 6. Closing prompt
    messages.push({
      id: `scan-close-${Date.now()}`,
      role: "agent",
      content: `Scan complete. You can ask me to explain any finding in detail, suggest remediation steps, or analyze attack vectors. Click "Ask AI →" on any finding card above, or type your question below.`,
      timestamp: now,
    });

    return messages;
  };

  // ─── Handle user chat follow-up messages via Autonomous MCP Agent ──────
  const handleChatMessage = async (message: string) => {
    const now = new Date().toLocaleTimeString("en-GB");

    // Add user message immediately
    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: message,
      timestamp: now,
    };

    // Pending agent message with dynamic thinking indicator
    const pendingId = `agent-pending-${Date.now()}`;
    const pendingMsg: ChatMessage = {
      id: pendingId,
      role: "agent",
      content: "Autonomous Open-Source Recon Agent analyzing intent & formulating search tool query...",
      timestamp: now,
      isStreaming: true,
    };

    setChatMessages((prev) => [...prev, userMsg, pendingMsg]);

    const target = scanResult?.summary?.target || initialTarget || "vulnweb.com";

    try {
      const rawApiUrl = process.env.NEXT_PUBLIC_API_URL || "";
      const cleanApiUrl = rawApiUrl.replace(/\/+$/, "");
      const chatEndpoint = cleanApiUrl ? `${cleanApiUrl}/api/mcp/chat` : "/api/mcp/chat";

      const res = await fetch(chatEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: target,
          message,
          existing_nodes: scanResult?.nodes || [],
        }),
      });

      if (!res.ok) {
        throw new Error(`MCP Chat returned HTTP ${res.status}`);
      }

      const data = await res.json();

      const newAgentMsg: ChatMessage = {
        id: `agent-${Date.now()}`,
        role: "agent",
        content: data.reply || "Recon investigation complete.",
        timestamp: new Date().toLocaleTimeString("en-GB"),
        findings: data.findings && data.findings.length > 0 ? data.findings : undefined,
        tool_call: data.tool_call || undefined,
        mcpResultsCount: data.mcp_results_count,
        thoughts: data.thought
          ? [
              {
                timestamp: new Date().toLocaleTimeString("en-GB"),
                stage: data.tool_call ? "MCP_TOOL_EXEC" : "MCP_REASONING",
                message: data.thought,
                status: data.tool_call ? "success" : "info",
              },
            ]
          : undefined,
      };

      // Replace pending message with completed agent response
      setChatMessages((prev) =>
        prev.map((m) => (m.id === pendingId ? newAgentMsg : m))
      );

      // If new findings discovered by the live tool call, integrate them into workspace scanResult
      if (data.findings && data.findings.length > 0) {
        setScanResult((prev) => {
          const existingIds = new Set(prev.nodes.map((n) => n.id));
          const uniqueNewNodes = data.findings.filter((n: GraphNode) => !existingIds.has(n.id));
          if (uniqueNewNodes.length === 0) return prev;

          return {
            ...prev,
            nodes: [...prev.nodes, ...uniqueNewNodes],
            summary: {
              ...prev.summary,
              total_nodes: (prev.summary.total_nodes || 0) + uniqueNewNodes.length,
            },
          };
        });
      }
    } catch (err: any) {
      console.warn("MCP Agent backend call failed:", err);
      const errorMsg: ChatMessage = {
        id: `agent-${Date.now()}`,
        role: "agent",
        content: "⚠️ **Agent Service Communication Error**: Unable to reach the backend MCP service at `http://localhost:8001/api/mcp/chat`. Please verify the backend service is running and accessible.",
        timestamp: new Date().toLocaleTimeString("en-GB"),
      };
      setChatMessages((prev) =>
        prev.map((m) => (m.id === pendingId ? errorMsg : m))
      );
    }
  };


  const executeScanRequest = async (
    domain: string,
    enablePhase2: boolean = true,
    customDorks: string[] = [],
    enabledVectors?: Record<string, boolean>,
    protocol: "rest" | "mcp" | "both" = "rest"
  ) => {
    setIsScanning(true);
    setSelectedNode(null);
    setExecutedProtocol(protocol);

    // If MCP or Both, add an initial chat message; if REST, clear previous chat messages
    if (protocol === "mcp" || protocol === "both") {
      setChatMessages([{
        id: `system-init-${Date.now()}`,
        role: "system",
        content: `Initializing ${protocol === "both" ? "Dual Engine (REST + Open-Source Agent)" : "Open-Source Recon Agent"} Protocol scan for ${domain}...`,
        timestamp: new Date().toLocaleTimeString("en-GB"),
      }]);
    } else {
      setChatMessages([]);
    }

    const startTime = new Date().toLocaleTimeString("en-GB");
    const protoLabel = protocol === "both" ? "Dual Engine (REST + Agent)" : protocol === "mcp" ? "Open-Source Agent Protocol" : "Direct REST";
    setThoughts([
      {
        timestamp: startTime,
        stage: "DISPATCH",
        message: `Deploying live open-source multi-engine recon agent for target: ${domain} via ${protoLabel}...`,
        status: "info",
      },
    ]);

    try {
      const rawApiUrl = process.env.NEXT_PUBLIC_API_URL || "";
      const cleanApiUrl = rawApiUrl.replace(/\/+$/, "");
      const scanEndpoint = cleanApiUrl ? `${cleanApiUrl}/api/scan` : "/api/scan";

      const res = await fetch(scanEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain,
          enable_phase2: enablePhase2,
          use_cache: false,
          custom_dorks: customDorks,
          enabled_vectors: enabledVectors,
          protocol,
        }),
      });

      if (res.ok) {
        const data: ScanResult = await res.json();

        setScanResult(data);
        if (data.thoughts && data.thoughts.length > 0) {
          setThoughts(data.thoughts);
        }

        // If MCP or Both protocol, build chat messages from scan results; otherwise keep chat clean
        if (protocol === "mcp" || protocol === "both") {
          const chatMsgs = buildChatMessagesFromScan(data, domain);
          setChatMessages(chatMsgs);
        } else {
          setChatMessages([]);
        }

      } else {
        throw new Error(`Endpoint ${scanEndpoint} returned HTTP ${res.status}`);
      }
    } catch (err: any) {
      console.error("Live scan failed:", err);
      const errorMsg = `Scan error: ${err?.message || "Failed to reach backend"}. Please check your backend URL configuration.`;
      setThoughts((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString("en-GB"),
          stage: "ERROR",
          message: errorMsg,
          status: "critical",
        },
      ]);

      // If MCP or Both, add error to chat
      if (protocol === "mcp" || protocol === "both") {
        setChatMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}`,
            role: "agent",
            content: `❌ ${errorMsg}`,
            timestamp: new Date().toLocaleTimeString("en-GB"),
          },
        ]);
      }
    } finally {
      setIsScanning(false);
    }
  };

  // Direct unauthenticated open-source scan execution
  const handleScan = (
    domain: string,
    enablePhase2: boolean = true,
    customDorks: string[] = [],
    enabledVectors?: Record<string, boolean>,
    protocol: "rest" | "mcp" | "both" = "rest"
  ) => {
    const cleanTarget = domain
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .replace(/^www\./, "");

    executeScanRequest(cleanTarget || "vulnweb.com", enablePhase2, customDorks, enabledVectors, protocol);
  };

  const handleToggleLayout = () => {
    setLayoutDirection((prev) => (prev === "TB" ? "LR" : "TB"));
  };

  const handleExportDossier = () => {
    if (!scanResult || scanResult.nodes.length === 0) return;
    const md = generateAuditDossier(scanResult);

    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ReconFlow_Dossier_${scanResult.summary.target || "audit"}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col font-mono selection:bg-lime/20 selection:text-lime transition-colors duration-200">
      {/* Top Application Workspace Bar */}
      <header className="fixed top-0 inset-x-0 z-40 bg-surface/95 backdrop-blur-md border-b border-border px-4 sm:px-6 py-3 transition-colors duration-200">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-1.5 text-xs text-foreground-secondary hover:text-foreground transition-colors p-1 rounded hover:bg-surface-elevated"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Landing</span>
            </Link>
            <div className="h-4 w-px bg-border" />
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-foreground tracking-tight">
                RECONFLOW<span className="text-lime">.AI</span>
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-surface-elevated border border-border text-foreground-muted">
                Workspace
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Open Source Status Badge */}
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-lime/15 border border-lime/30 text-lime text-[10px] font-bold tracking-wider">
              <span className="w-2 h-2 rounded-full bg-lime animate-pulse" />
              <span>100% OPEN SOURCE // UNLIMITED</span>
            </span>

            {/* Theme Toggle (Light / Dark mode) */}
            <ThemeToggle />

            {/* Export Dossier */}
            <button
              onClick={handleExportDossier}
              className="flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-md bg-surface hover:bg-surface-elevated text-foreground border border-border shadow-sm transition-all cursor-pointer"
              title="Download executive audit dossier markdown"
            >
              <Download className="w-3.5 h-3.5 text-lime" />
              <span className="hidden sm:inline">Export Dossier</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Workspace Body */}
      <main className="flex-1 pt-20 pb-16 px-4 max-w-7xl w-full mx-auto space-y-6">

        {/* Workspace Title & Purpose */}
        <div className="max-w-3xl pt-4">
          <div className="inline-flex items-center gap-2 text-xs font-mono text-foreground-muted uppercase tracking-wider mb-2">
            <span>Autonomous Reconnaissance // Live Canvas</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">
            Interactive Attack-Surface Topology
          </h1>
          <p className="mt-1.5 text-xs text-foreground-secondary font-sans">
            Audit external perimeters, correlate multi-engine search dorks, inspect CVSS/OWASP vulnerability evidence, and execute defensive playbooks.
          </p>
        </div>



        {/* Search Bar & Controls */}
        <SearchBar
          onScan={handleScan}
          isScanning={isScanning}
          protocol={selectedProtocol}
          onProtocolChange={(p) => {
            setSelectedProtocol(p);
          }}
        />

        {/* Executive Threat Briefing Callout */}
        {scanResult?.executive_summary && (
          <div className="p-4 rounded-lg bg-surface border border-border flex items-start gap-3.5 shadow-sm font-mono text-xs">
            <div className="p-2 rounded bg-surface-elevated text-foreground-secondary mt-0.5 border border-border">
              <Sparkles className="w-4 h-4 text-lime" />
            </div>
            <div className="flex-1 leading-relaxed text-foreground-secondary font-sans">
              <span className="font-bold text-foreground block mb-1 font-mono uppercase tracking-wider text-[11px]">
                Executive Threat Briefing
              </span>
              {scanResult.executive_summary}
            </div>
          </div>
        )}

        {/* Metric Summary Cards (Shown for REST and Both modes) */}
        {displayMode !== "mcp" && scanResult?.summary && (
          <SummaryCards
            summary={scanResult.summary}
            activeFilter={activeFilter}
            onFilterChange={setActiveFilter}
          />
        )}

        {/* Conditional Workspace Engine Views (Strict Mode Isolation) */}
        {displayMode === "both" ? (
          <>
            {/* THIRD OPTION: RUN BOTH (DUAL HYBRID MODE) - Includes View Switcher */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-2.5 rounded-xl bg-surface border border-cyan-500/30 shadow-sm">
              <div className="flex items-center gap-1.5 flex-wrap">
                <button
                  type="button"
                  onClick={() => setBothActiveView("graph")}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-mono text-xs font-bold transition-all cursor-pointer ${
                    bothActiveView === "graph"
                      ? "bg-surface-elevated text-foreground border border-border shadow-sm ring-1 ring-border"
                      : "text-foreground-muted hover:text-foreground hover:bg-surface-elevated/50 border border-transparent"
                  }`}
                >
                  <Network className="w-3.5 h-3.5 text-lime" />
                  <span>Interactive Topology Graph</span>
                  {scanResult?.nodes?.length > 0 && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                      {scanResult.nodes.length} nodes
                    </span>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setBothActiveView("chat");
                    if (chatMessages.length === 0 && scanResult?.nodes?.length > 0 && scanResult?.summary?.protocol_used === "both") {
                      setChatMessages(buildChatMessagesFromScan(scanResult, scanResult.summary.target));
                    }
                  }}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-mono text-xs font-bold transition-all cursor-pointer ${
                    bothActiveView === "chat"
                      ? "bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/40 shadow-sm ring-1 ring-purple-500/30"
                      : "text-foreground-muted hover:text-foreground hover:bg-surface-elevated/50 border border-transparent"
                  }`}
                >
                  <Bot className="w-3.5 h-3.5 text-purple-500" />
                  <span>Open-Source AI Chat Digest</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-700 dark:text-purple-300 font-bold">
                    Chat Interface
                  </span>
                </button>
              </div>

              <div className="flex items-center gap-2 text-[11px] font-mono text-cyan-700 dark:text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1.5 rounded-lg">
                <Sparkles className="w-3.5 h-3.5 text-cyan-500 animate-spin" style={{ animationDuration: "6s" }} />
                <span>
                  {scanResult?.summary?.protocol_used === "both"
                    ? "Dual Protocol Active · Both Graph & AI Chat Enabled"
                    : "Dual Protocol Mode Selected · Both Graph & AI Chat Tabs Available"}
                </span>
              </div>
            </div>

            {/* Render Dual Mode Active Tab */}
            {bothActiveView === "chat" ? (
              <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                <div className="lg:col-span-3">
                  <MCPChatPanel
                    messages={chatMessages}
                    onSendMessage={handleChatMessage}
                    isScanning={isScanning}
                    scanResult={scanResult}
                  />
                </div>
                <div className="lg:col-span-2">
                  <MCPFindingsSidebar
                    summary={scanResult?.summary?.total_nodes > 0 ? scanResult.summary : null}
                    onAskAbout={handleChatMessage}
                  />
                </div>
              </div>
            ) : (
              <div className="relative">
                <GraphCanvas
                  nodes={layoutedNodes}
                  edges={layoutedEdges}
                  onNodeClick={setSelectedNode}
                  selectedNodeId={selectedNode?.id}
                  layoutDirection={layoutDirection}
                  onToggleLayout={handleToggleLayout}
                />
                <FindingDrawer node={selectedNode} onClose={() => setSelectedNode(null)} />
              </div>
            )}
          </>
        ) : displayMode === "mcp" ? (
          <>
            {/* OPTION 2: OPEN-SOURCE AGENT ONLY - AI CHAT DIGEST ONLY (No Graph, No Switcher) */}
            <div className="flex items-center justify-between px-3.5 py-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-xs font-mono text-purple-700 dark:text-purple-300">
              <div className="flex items-center gap-2.5">
                <Bot className="w-4 h-4 text-purple-500" />
                <span className="font-bold">Open-Source Agent Mode Active</span>
                <span className="hidden sm:inline text-[11px] text-foreground-muted">· Conversational AI Digest</span>
              </div>
              <div className="flex items-center gap-2">
                {selectedProtocol !== "mcp" && executedProtocol === "mcp" && (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                    Staged: {selectedProtocol === "both" ? "Dual Mode" : "Direct REST"} (Click Execute to run)
                  </span>
                )}
                <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 font-bold border border-purple-500/40">
                  MCP Chat Only
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
              <div className="lg:col-span-3">
                <MCPChatPanel
                  messages={chatMessages}
                  onSendMessage={handleChatMessage}
                  isScanning={isScanning}
                  scanResult={scanResult}
                />
              </div>
              <div className="lg:col-span-2">
                <MCPFindingsSidebar
                  summary={
                    scanResult?.summary?.protocol_used === "mcp" && (scanResult?.summary?.total_nodes ?? 0) > 0
                      ? scanResult.summary
                      : null
                  }
                  onAskAbout={handleChatMessage}
                />
              </div>
            </div>
          </>
        ) : (
          <>
            {/* OPTION 1: DIRECT REST API ONLY - TOPOLOGY GRAPH CANVAS ONLY (No Chat, No Switcher) */}
            <div className="flex items-center justify-between px-3.5 py-2.5 rounded-xl bg-surface border border-border text-xs font-mono text-foreground-secondary">
              <div className="flex items-center gap-2.5">
                <Network className="w-4 h-4 text-lime" />
                <span className="font-bold text-foreground">Direct REST Mode Active</span>
                <span className="hidden sm:inline text-[11px] text-foreground-muted">· Interactive Node Topology Canvas (Raw JSON)</span>
              </div>
              <div className="flex items-center gap-2">
                {selectedProtocol !== "rest" && executedProtocol === "rest" && (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                    Staged: {selectedProtocol === "both" ? "Dual Mode" : "Open-Source Agent"} (Click Execute to run)
                  </span>
                )}
                <span className="text-[10px] px-2 py-0.5 rounded bg-surface-elevated border border-border text-foreground-muted font-bold">
                  REST Graph Only
                </span>
              </div>
            </div>

            <div className="relative">
              <GraphCanvas
                nodes={layoutedNodes}
                edges={layoutedEdges}
                onNodeClick={setSelectedNode}
                selectedNodeId={selectedNode?.id}
                layoutDirection={layoutDirection}
                onToggleLayout={handleToggleLayout}
              />
              <FindingDrawer node={selectedNode} onClose={() => setSelectedNode(null)} />
            </div>
          </>
        )}

        {/* Autonomous Agent Thought Stream (Only for Direct REST and Both modes, NEVER for MCP mode) */}
        {displayMode !== "mcp" && (
          <ThoughtStream thoughts={thoughts} isScanning={isScanning} />
        )}
      </main>



    </div>
  );
}

export default function ReconPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background flex items-center justify-center font-mono text-xs text-foreground-muted">
          <div className="flex items-center gap-2">
            <span className="w-3.5 h-3.5 border-2 border-lime border-t-transparent rounded-full animate-spin" />
            <span>Loading ReconFlow Workspace...</span>
          </div>
        </div>
      }
    >
      <ReconWorkspaceContent />
    </Suspense>
  );
}
