"use client";

import React from "react";
import { useRouter } from "next/navigation";

import { Navbar } from "@/components/Navbar";
import { HeroSection } from "@/components/HeroSection";
import { ProblemSection } from "@/components/ProblemSection";
import { HowItWorksSection } from "@/components/HowItWorksSection";
import { RemediationSection } from "@/components/RemediationSection";
import { CapabilitiesSection } from "@/components/CapabilitiesSection";
import { OpenSourceSection } from "@/components/OpenSourceSection";
import { FinalCTASection } from "@/components/FinalCTASection";
import { Footer } from "@/components/Footer";

export default function Home() {
  const router = useRouter();

  const handleStartRecon = (target: string = "vulnweb.com") => {
    const clean = target.trim() || "vulnweb.com";
    router.push(`/recon?target=${encodeURIComponent(clean)}`);
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col font-sans selection:bg-lime/20 selection:text-lime transition-colors duration-200">
      {/* Top Navbar */}
      <Navbar onStartReconClick={() => handleStartRecon("vulnweb.com")} />

      {/* Hero Section with Three.js Particle Wave */}
      <HeroSection onScanTarget={handleStartRecon} isScanning={false} />

      {/* Section 1: The Perimeter Problem & Live OSINT Terminal */}
      <ProblemSection />

      {/* Section 2: Autonomous Methodology (How It Works) */}
      <HowItWorksSection />

      {/* Section 3: Actionable Triage & Defensive Playbook */}
      <RemediationSection />

      {/* Section 4: 6 Core Capabilities */}
      <CapabilitiesSection />

      {/* Section 5: 100% Free & Open-Source — Better Than Commercial APIs */}
      <OpenSourceSection />

      {/* Section 6: Final CTA */}
      <FinalCTASection onScanTarget={handleStartRecon} />

      {/* Footer */}
      <Footer />
    </div>
  );
}
