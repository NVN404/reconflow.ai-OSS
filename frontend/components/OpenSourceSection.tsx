"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Check,
  Shield,
  Sparkles,
  Terminal,
  ArrowRight,
  Copy,
  CheckCheck,
  Cpu,
  RefreshCw,
  GitBranch,
  KeyRound,
  MailCheck,
  CreditCard,
  Lock,
} from "lucide-react";
import { motion } from "framer-motion";

export const OpenSourceSection: React.FC = () => {
  const router = useRouter();
  const [copiedInstall, setCopiedInstall] = useState(false);

  const handleCopyCommand = () => {
    navigator.clipboard.writeText("git clone https://github.com/NVN404/reconflow.ai-OSS.git && cd reconflow.ai-OSS && ./start_dev.sh");
    setCopiedInstall(true);
    setTimeout(() => setCopiedInstall(false), 2500);
  };

  const freedomGuarantees = [
    {
      icon: <CreditCard className="w-5 h-5 text-lime" />,
      title: "Zero Paywalls ($0 Free Forever)",
      badge: "NO BILLING",
      description: "No subscription plans, trial limits, query credits, or credit card requirements. 100% free under the MIT License.",
    },
    {
      icon: <KeyRound className="w-5 h-5 text-sky-400" />,
      title: "Zero Authentication Needed",
      badge: "NO LOGIN",
      description: "No account creation, passwords, or session tokens. Clone the repository and immediately launch reconnaissance sweeps.",
    },
    {
      icon: <MailCheck className="w-5 h-5 text-emerald-400" />,
      title: "No Work Email Authorization",
      badge: "NO GATES",
      description: "No corporate email verification barriers or corporate domain whitelisting. Audit any perimeter with complete freedom.",
    },
    {
      icon: <Lock className="w-5 h-5 text-purple-400" />,
      title: "100% Local Data Sovereignty",
      badge: "ZERO TELEMETRY",
      description: "Your targets, security dorks, and reconnaissance graph stay entirely on your machine. Zero queries logged to external cloud servers.",
    },
  ];

  const pillars = [
    {
      icon: <Terminal className="w-5 h-5 text-lime" />,
      title: "Multi-Engine Search Triad",
      badge: "OPEN SOURCE",
      description:
        "Harvests surface intelligence across DuckDuckGo, Google organic results, and Certificate Transparency (crt.sh) with zero commercial API dependencies.",
    },
    {
      icon: <RefreshCw className="w-5 h-5 text-sky-400" />,
      title: "Self-Healing Proxy Rotation",
      badge: "AUTO-QUARANTINE",
      description:
        "Built-in proxy rotation pool with sub-second pre-flight benchmarking, automated circuit breakers, and 300s quarantine to prevent rate limiting.",
    },
    {
      icon: <Shield className="w-5 h-5 text-emerald-400" />,
      title: "Passive & Non-Intrusive OSINT",
      badge: "STEALTH",
      description:
        "Performs passive discovery against public records, search indices, and DNS tables with zero invasive penetration payloads or unauthorized disruption.",
    },
    {
      icon: <Cpu className="w-5 h-5 text-purple-400" />,
      title: "Native MCP JSON-RPC 2.0 Server",
      badge: "AI READY",
      description:
        "Includes a standardized Model Context Protocol (MCP) server ready to integrate with Claude Desktop, Cursor, Gemini, or autonomous CLI agents.",
    },
  ];

  return (
    <section id="open-source" className="py-24 px-4 bg-background border-b border-border relative overflow-hidden font-mono">
      {/* Subtle background glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-lime/5 blur-[120px] rounded-full pointer-events-none" />

      <div className="max-w-7xl mx-auto relative z-10 space-y-16">
        {/* Section Header */}
        <div className="max-w-3xl mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-lime/10 border border-lime/30 text-lime text-xs font-bold tracking-wider">
            <span className="w-2 h-2 rounded-full bg-lime animate-pulse" />
            <span>05 // 100% FREE &amp; OPEN SOURCE ARCHITECTURE</span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-bold tracking-tight text-foreground font-sans leading-tight">
            Clone, Run, and Audit in <span className="text-lime">30 Seconds</span>.
          </h2>

          <p className="text-base sm:text-lg text-foreground-secondary font-sans leading-relaxed">
            Zero paywalls. Zero authentication. Zero corporate email gates. Just pure, unconstrained open-source external attack surface intelligence.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2 text-xs">
            <span className="px-3 py-1 rounded-md bg-surface-elevated border border-border text-foreground font-bold flex items-center gap-1.5 shadow-sm">
              <Check className="w-3.5 h-3.5 text-lime" />
              MIT Open Source License
            </span>
            <span className="px-3 py-1 rounded-md bg-surface-elevated border border-border text-foreground font-bold flex items-center gap-1.5 shadow-sm">
              <Check className="w-3.5 h-3.5 text-lime" />
              $0 / Free Forever
            </span>
            <span className="px-3 py-1 rounded-md bg-surface-elevated border border-border text-foreground font-bold flex items-center gap-1.5 shadow-sm">
              <Check className="w-3.5 h-3.5 text-lime" />
              Zero Sign-Up Required
            </span>
            <span className="px-3 py-1 rounded-md bg-surface-elevated border border-border text-foreground font-bold flex items-center gap-1.5 shadow-sm">
              <Check className="w-3.5 h-3.5 text-lime" />
              No Work Email Gate
            </span>
            <span className="px-3 py-1 rounded-md bg-surface-elevated border border-border text-foreground font-bold flex items-center gap-1.5 shadow-sm">
              <Check className="w-3.5 h-3.5 text-lime" />
              Unlimited Recon Scans
            </span>
          </div>
        </div>

        {/* Quickstart Terminal Card (Prominent Front & Center) */}
        <div className="p-6 sm:p-8 rounded-2xl bg-surface border-2 border-lime/30 shadow-xl shadow-lime/5 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-2 max-w-xl text-center md:text-left">
            <div className="flex items-center justify-center md:justify-start gap-2 text-xs text-lime font-bold">
              <Terminal className="w-4 h-4" />
              <span>Clone &amp; Run Locally in One Line</span>
            </div>
            <h3 className="text-xl sm:text-2xl font-bold text-foreground font-sans">
              No Accounts. No API Keys. Just Clone &amp; Use.
            </h3>
            <p className="text-xs text-foreground-secondary font-sans leading-relaxed">
              Run the full autonomous reconnaissance pipeline on macOS, Linux, or Docker. No registration, credit cards, or verification needed.
            </p>

            <div className="pt-2 flex items-center gap-2 bg-surface-elevated p-3 rounded-lg border border-border text-xs text-foreground-muted font-mono overflow-x-auto">
              <span className="text-lime font-bold">$</span>
              <span className="text-foreground select-all text-[11px]">
                git clone https://github.com/NVN404/reconflow.ai-OSS.git &amp;&amp; cd reconflow.ai-OSS &amp;&amp; ./start_dev.sh
              </span>
              <button
                type="button"
                onClick={handleCopyCommand}
                className="ml-auto p-1.5 rounded hover:bg-surface text-foreground-secondary hover:text-foreground transition-colors cursor-pointer flex-shrink-0"
                title="Copy shell command"
              >
                {copiedInstall ? (
                  <CheckCheck className="w-4 h-4 text-lime" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto flex-shrink-0">
            <button
              onClick={() => router.push("/recon")}
              className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-lime hover:opacity-90 text-background font-bold text-xs flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-lime/10 transition-all active:scale-95"
            >
              <span>Launch Instant Recon</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <a
              href="https://github.com/NVN404/reconflow.ai-OSS"
              target="_blank"
              rel="noreferrer"
              className="w-full sm:w-auto px-5 py-3.5 rounded-xl bg-surface hover:bg-surface-elevated text-foreground border border-border font-bold text-xs flex items-center justify-center gap-2 transition-all cursor-pointer"
            >
              <GitBranch className="w-4 h-4 text-foreground-muted" />
              <span>GitHub (MIT)</span>
            </a>
          </div>
        </div>

        {/* 4 Zero-Friction Freedom Guarantees */}
        <div className="space-y-4">
          <div className="text-center sm:text-left">
            <h3 className="text-xl sm:text-2xl font-bold text-foreground font-sans">
              Zero-Friction Guarantees
            </h3>
            <p className="text-xs text-foreground-secondary font-sans mt-0.5">
              Built by security practitioners for practitioners. Zero barriers between you and your reconnaissance graph.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {freedomGuarantees.map((item, i) => (
              <motion.div
                key={i}
                whileHover={{ y: -3 }}
                className="p-5 rounded-xl bg-surface border border-border hover:border-lime/40 transition-all flex flex-col justify-between space-y-4 shadow-sm"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="p-2 rounded-lg bg-surface-elevated border border-border">
                      {item.icon}
                    </div>
                    <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-surface-elevated border border-border text-lime">
                      {item.badge}
                    </span>
                  </div>
                  <h4 className="font-bold text-foreground text-sm font-sans">
                    {item.title}
                  </h4>
                  <p className="text-xs text-foreground-secondary font-sans leading-relaxed">
                    {item.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* 4 Architectural Engineering Pillars Grid */}
        <div className="space-y-4">
          <div className="text-center sm:text-left">
            <h3 className="text-xl sm:text-2xl font-bold text-foreground font-sans">
              Under the Hood: Open-Source Architecture
            </h3>
            <p className="text-xs text-foreground-secondary font-sans mt-0.5">
              How ReconFlow AI achieves high throughput and ban-resilience with completely free, transparent tooling.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {pillars.map((pillar, i) => (
              <motion.div
                key={i}
                whileHover={{ y: -3 }}
                className="p-5 rounded-xl bg-surface border border-border hover:border-lime/40 transition-all flex flex-col justify-between space-y-4 shadow-sm"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="p-2 rounded-lg bg-surface-elevated border border-border">
                      {pillar.icon}
                    </div>
                    <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-surface-elevated border border-border text-foreground-muted">
                      {pillar.badge}
                    </span>
                  </div>
                  <h4 className="font-bold text-foreground text-sm font-sans">
                    {pillar.title}
                  </h4>
                  <p className="text-xs text-foreground-secondary font-sans leading-relaxed">
                    {pillar.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};
