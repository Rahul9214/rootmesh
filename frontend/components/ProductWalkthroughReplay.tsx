"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";

export interface WalkthroughStep {
  id: number;
  phase: string;
  title: string;
  summary: string;
  findingBadge: string;
  badgeColor: string;
  telemetry: {
    label: string;
    value: string;
  }[];
  explanation: string;
}

const WALKTHROUGH_STEPS: WalkthroughStep[] = [
  {
    id: 1,
    phase: "01 · ASSET IDENTIFICATION",
    title: "Asset Selected",
    summary: "Suspicious lateral activity flagged on perimeter workstation node.",
    findingBadge: "Target Identified",
    badgeColor: "bg-[#FBF0ED] text-[#D26A50] border-[#F3C4B8]",
    telemetry: [
      { label: "Selected Node", value: "Workstation-04 (Host ID: host-0)" },
      { label: "Segment", value: "Corporate VLAN-10 (Tier-3 Edge)" },
      { label: "Network Centrality", value: "0.082 (Peripheral Host)" },
    ],
    explanation:
      "Investigation initiates from a verified inventory asset rather than an ungrounded alert. The security analyst selects the suspicious workstation to map forward propagation reach.",
  },
  {
    id: 2,
    phase: "02 · GRAPH TOPOLOGY TRAVERSAL",
    title: "Connections Analyzed",
    summary: "Graph topology traversal discovers 3 reachable downstream hops across active network links.",
    findingBadge: "3 Lateral Hops",
    badgeColor: "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]",
    telemetry: [
      { label: "Traversal Depth", value: "3 hops (shortest-path propagation)" },
      { label: "Reachable Nodes", value: "AppServer-Internal, JumpServer-SysAdmin, ReverseProxy" },
      { label: "Evaluation Time", value: "1.4 ms (In-Memory Topology Traversal)" },
    ],
    explanation:
      "Instead of inspecting isolated host logs, RootMesh traverses actual network communication edges in the tenant graph model to calculate exactly which assets the threat could reach laterally.",
  },
  {
    id: 3,
    phase: "03 · HIGH-VALUE ASSET IMPACT",
    title: "Potential Impact Identified",
    summary: "Forward path identified terminating at restricted payroll database and egress firewall bottleneck.",
    findingBadge: "High-Value Database Exposed",
    badgeColor: "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]",
    telemetry: [
      { label: "Target Database", value: "HR-Payroll-DB (Restricted / PII)" },
      { label: "Egress Capacity", value: "1,200 Mbps (Network Flow Bottleneck)" },
      { label: "Criticality Tier", value: "Tier-1 Critical Infrastructure" },
    ],
    explanation:
      "RootMesh determines the ultimate business risk: Does an attack path lead to high-value data? Here, an unsegmented pivot exposes the core employee database within 3 network hops.",
  },
  {
    id: 4,
    phase: "04 · ORGANIZATIONAL OWNERSHIP MAPPING",
    title: "Response Owner Resolved",
    summary: "Company Brain maps technical assets to the responsible engineering team and remediation runbook.",
    findingBadge: "Owner Resolved",
    badgeColor: "bg-[#F6EDF1] text-[#82465D] border-[#E5CDD8]",
    telemetry: [
      { label: "Responsible Team", value: "Core Infrastructure SecOps" },
      { label: "On-Call Responder", value: "Sarah Chen (Primary On-Call)" },
      { label: "Remediation Guide", value: "RB-NET-084: Lateral VLAN Severance" },
    ],
    explanation:
      "Technical context is fused with organizational intelligence. The incident responder knows immediately who owns the system, who is on call, and which approved runbook governs remediation.",
  },
  {
    id: 5,
    phase: "05 · GUARDED HUMAN REVIEW",
    title: "Human Review Required",
    summary: "Mitigation proposal formulated. Containment simulation requires explicit authorized review.",
    findingBadge: "Human Review Required",
    badgeColor: "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]",
    telemetry: [
      { label: "Proposed Action", value: "GRAPH_TOPOLOGY_SIMULATION (Sever 3 Lateral Edges)" },
      { label: "Egress Reduction", value: "1,200 Mbps Egress Risk Mitigated" },
      { label: "Safety Gate", value: "Fail-Closed: No unilateral autonomous action without review" },
    ],
    explanation:
      "RootMesh enforces separation of duties. The system proposes precise topological isolation, but never takes destructive action autonomously. An authorized human must review and execute.",
  },
];

export function ProductWalkthroughReplay() {
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [isCompleted, setIsCompleted] = useState<boolean>(false);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState<boolean>(false);

  const containerRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Check reduced motion preference
  useEffect(() => {
    if (typeof window !== "undefined") {
      const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
      setPrefersReducedMotion(mediaQuery.matches);
      if (mediaQuery.matches) {
        setIsPlaying(false);
      }
    }
  }, []);

  // IntersectionObserver: Pause when offscreen
  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof IntersectionObserver === "undefined") return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting && isPlaying) {
            setIsPlaying(false);
          }
        });
      },
      { threshold: 0.2 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [isPlaying]);

  // Step advancement timer
  useEffect(() => {
    if (prefersReducedMotion || !isPlaying || isCompleted) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev >= WALKTHROUGH_STEPS.length - 1) {
          setIsCompleted(true);
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 4200);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, isCompleted, prefersReducedMotion]);

  const handleReplay = useCallback(() => {
    setCurrentStepIndex(0);
    setIsCompleted(false);
    setIsPlaying(true);
  }, []);

  const handleTogglePlay = useCallback(() => {
    if (isCompleted) {
      handleReplay();
      return;
    }
    setIsPlaying((prev) => !prev);
  }, [isCompleted, handleReplay]);

  const handleSelectStep = useCallback((index: number) => {
    setCurrentStepIndex(index);
    setIsCompleted(index === WALKTHROUGH_STEPS.length - 1);
  }, []);

  const activeStep = WALKTHROUGH_STEPS[currentStepIndex];

  return (
    <div
      ref={containerRef}
      id="product-walkthrough"
      className="scroll-mt-24 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-md overflow-hidden"
      aria-label="Interactive Product Walkthrough"
    >
      {/* ── Walkthrough Header / Control Bar ────────────────────────────── */}
      <div className="px-5 sm:px-6 py-4 border-b border-[#EEE6DC] bg-[#FAF7F2] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#D26A50] animate-pulse" />
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#302B30]">
            Interactive Walkthrough — Continuous Evidence Assembly
          </span>
          <span className="hidden sm:inline-block text-[11px] font-mono px-2 py-0.5 rounded bg-[#F5EFE6] text-[#82465D] border border-[#DFD6C9]">
            Conceptual Demonstration
          </span>
        </div>

        {/* Playback Controls */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleTogglePlay}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] text-[#302B30] text-xs font-mono font-medium border border-[#DFD6C9] transition-colors cursor-pointer"
            aria-label={isPlaying ? "Pause walkthrough" : isCompleted ? "Replay walkthrough" : "Resume walkthrough"}
          >
            <span>{isPlaying ? "⏸ Pause" : isCompleted ? "↺ Replay" : "▶ Resume"}</span>
          </button>

          <button
            type="button"
            onClick={handleReplay}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] text-[#82465D] text-xs font-mono font-medium border border-[#DFD6C9] transition-colors cursor-pointer"
            title="Reset from Step 1"
            aria-label="Reset walkthrough to Step 1"
          >
            <span aria-hidden="true">↺</span>
            <span className="hidden sm:inline">Reset</span>
          </button>
        </div>
      </div>

      {/* ── Progress Scrubber (Clickable Timeline Tabs) ─────────────────── */}
      <div className="border-b border-[#EEE6DC] bg-[#FAF7F2]/60 px-4 sm:px-6 py-2.5 overflow-x-auto">
        <div className="flex items-center gap-1.5 sm:gap-2 min-w-max">
          {WALKTHROUGH_STEPS.map((step, idx) => {
            const isActive = idx === currentStepIndex;
            const isPast = idx < currentStepIndex;

            return (
              <button
                key={step.id}
                type="button"
                onClick={() => handleSelectStep(idx)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                  isActive
                    ? "bg-[#D26A50] text-white font-semibold shadow-warm-xs"
                    : isPast
                    ? "bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]"
                    : "bg-[#FFFFFF] text-[#645C64] hover:bg-[#F5EFE6] border border-[#DFD6C9]"
                }`}
                aria-current={isActive ? "step" : undefined}
                aria-label={`${step.id} ${step.title}`}
              >
                <span className="font-bold">{step.id}</span>
                <span className="hidden md:inline truncate max-w-[140px]">{step.title}</span>
                {isPast && <span aria-hidden="true">✓</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Main Walkthrough Display Stage ───────────────────────────────── */}
      <div className="p-6 sm:p-8 space-y-6">
        {/* Step Banner */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <span className="text-xs font-mono font-semibold tracking-wider text-[#D26A50]">
              {activeStep.phase}
            </span>
            <h3 className="text-xl sm:text-2xl font-extrabold text-[#302B30]">
              {activeStep.title}
            </h3>
            <p className="text-sm text-[#645C64]">{activeStep.summary}</p>
          </div>

          <span
            className={`text-xs font-mono font-bold px-3 py-1 rounded-full border ${activeStep.badgeColor}`}
          >
            {activeStep.findingBadge}
          </span>
        </div>

        {/* Simulated Telemetry Ribbon */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-4 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9]">
          {activeStep.telemetry.map((item, i) => (
            <div key={i} className="space-y-0.5">
              <span className="text-[10px] font-mono text-[#928992] uppercase tracking-wider block">
                {item.label}
              </span>
              <strong className="text-xs font-mono text-[#302B30] block truncate">
                {item.value}
              </strong>
            </div>
          ))}
        </div>

        {/* Architectural Explanation */}
        <div className="p-4 rounded-xl bg-[#F5EFE6]/60 border border-[#DFD6C9] text-xs text-[#302B30] leading-relaxed">
          <p className="font-sans">{activeStep.explanation}</p>
        </div>

        {/* Flow Indicator Dots & Accessibility Notice */}
        <div className="pt-2 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-[#928992] border-t border-[#EEE6DC]">
          <div className="flex items-center gap-1.5">
            <span>Progress:</span>
            <div className="flex items-center gap-1">
              {WALKTHROUGH_STEPS.map((_, i) => (
                <span
                  key={i}
                  className={`w-2 h-2 rounded-full transition-all ${
                    i === currentStepIndex
                      ? "w-5 bg-[#D26A50]"
                      : i < currentStepIndex
                      ? "bg-[#26694E]"
                      : "bg-[#DFD6C9]"
                  }`}
                />
              ))}
            </div>
            <span className="ml-1 text-[#645C64]">
              ({currentStepIndex + 1} of {WALKTHROUGH_STEPS.length})
            </span>
          </div>

          <span className="italic">
            * Purely educational product walkthrough. No backend credentials or tenant data involved.
          </span>
        </div>
      </div>
    </div>
  );
}
