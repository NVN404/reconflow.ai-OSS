"use client";

import React from "react";

export const Footer: React.FC = () => {
  return (
    <footer className="bg-background py-12 px-4 border-t border-border font-mono text-xs">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
        <div className="space-y-2 max-w-sm">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-foreground tracking-tight">
              RECONFLOW<span className="text-lime">.AI</span>
            </span>
          </div>
          <p className="text-foreground-muted text-xs font-sans leading-relaxed">
            Autonomous external attack-surface discovery and threat intelligence powered by open-source search tools.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-8 text-foreground-secondary">
          <a href="#problem" className="hover:text-foreground transition-colors">The Problem</a>
          <a href="/recon" className="hover:text-foreground transition-colors">Attack Surface Graph</a>
          <a href="#how-it-works" className="hover:text-foreground transition-colors">How It Works</a>
          <a href="#open-source" className="hover:text-foreground transition-colors flex items-center gap-1.5">
            <span>Open Source Architecture</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-lime/10 text-lime font-mono font-bold">
              $0 FREE
            </span>
          </a>
        </div>
      </div>

      <div className="max-w-7xl mx-auto pt-8 mt-8 border-t border-border flex flex-col sm:flex-row items-center justify-between text-[11px] text-foreground-muted gap-4">
        <div>
          &copy; {new Date().getFullYear()} ReconFlow.AI. Autonomous Attack Surface Management.
        </div>
        <div className="flex items-center gap-4">
          <span>Non-Intrusive Hybrid EASM</span>
          <span>|</span>
          <span className="text-lime font-semibold">100% Free &amp; Open-Source (MIT License)</span>
        </div>
      </div>
    </footer>
  );
};
