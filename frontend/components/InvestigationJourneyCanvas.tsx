"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import { useReducedMotion } from "framer-motion";
import type { InvestigationSummary, TopologyAsset } from "./HeroSection";

export interface InvestigationJourneyCanvasProps {
  summary: InvestigationSummary | null;
  selectedAsset: TopologyAsset | null;
  loading: boolean;
  onInvestigate?: () => void;
  resolvedTenant: string;
  organizationName?: string;
  persistedIncidentId?: string;
  persistedFindings?: Array<{ text: string }>;
}

/**
 * RootMesh Signature Investigation Journey Canvas (Step 3BM.2 Redesign)
 *
 * Continuous architectural SVG investigation path connecting 4 verified stages:
 *  01. ORIGIN ASSET (Selected verified target asset)
 *  02. LATERAL EXPOSURE (Reachable host vectors evaluated in topology)
 *  03. DATA PROXIMITY (High-value database vector & hop distance)
 *  04. GOVERNANCE GATEWAY (Verified owning team & runbook SLA)
 *
 * Enhancements:
 * - Continuous flowing SVG investigation path instead of 4 generic boxed cards.
 * - Single authoritative investigation trigger (no duplicate submission buttons).
 * - Truthful evidence states: "No forward path in evaluated graph (4 hops)" when shortest_path_db is null.
 * - Truthful governance: "Owner not resolved" when Company Brain owner is unverified.
 * - Reduced-motion fallback and stable min-height for CLS prevention.
 */
export const InvestigationJourneyCanvas: React.FC<InvestigationJourneyCanvasProps> = ({
  summary,
  selectedAsset,
  loading,
  resolvedTenant,
  organizationName,
  persistedIncidentId,
  persistedFindings,
}) => {
  const shouldReduceMotion = useReducedMotion();

  // Active investigation data derived strictly from authentic backend response
  const activeIncidentId = summary?.incident_id || persistedIncidentId || null;
  const isCompleted = Boolean(summary);
  const targetCount = summary?.target_count ?? 0;
  const execTime = summary?.execution_time_ms ?? 0;
  const dbInfo = summary?.shortest_path_db;
  const brain = summary?.company_brain;
  const egressRisk = summary?.egress_risk_mbps ?? 0;

  // ── Construct Genuine Sanitized Evidence Text for Auto-Completion Reveal ──
  const authenticEvidenceText = useMemo(() => {
    if (!summary) {
      if (persistedFindings && persistedFindings.length > 0) {
        return persistedFindings[0].text;
      }
      return "";
    }
    const pzName = summary.patient_zero_name || selectedAsset?.name || "Target Host";
    const pzId = summary.patient_zero_id || selectedAsset?.id || "host-0";
    const dbText = dbInfo
      ? `${dbInfo.db_name} (${dbInfo.classification || "RESTRICTED"}, ${
          dbInfo.distance === 0 ? "co-located" : `${dbInfo.distance}h reach`
        })`
      : "No forward path to restricted databases in evaluated graph (4 hops)";
    const brainText = brain?.team_name
      ? `Owner: ${brain.team_name} (Lead: ${brain.person_name || "Unassigned"}, SLA: ${
          brain.runbook_sla_minutes || 15
        }m)`
      : "Owner not resolved in Company Brain";

    return `Autonomous FalkorDB sweep evaluated ${pzName} (${pzId}) in ${execTime.toFixed(
      1
    )}ms. ${targetCount} lateral vector(s) identified with ${egressRisk} Mbps simulated perimeter egress. ${dbText}. ${brainText}.`;
  }, [summary, persistedFindings, selectedAsset, dbInfo, brain, targetCount, execTime, egressRisk]);

  // ── Tasteful Single-Location Typewriter Reveal Interaction ──
  const [typedText, setTypedText] = useState<string>("");
  const [isTypingComplete, setIsTypingComplete] = useState<boolean>(false);
  const prevSummaryIncidentRef = useRef<string | null>(null);

  useEffect(() => {
    if (!summary || !authenticEvidenceText) {
      setTypedText("");
      setIsTypingComplete(false);
      prevSummaryIncidentRef.current = null;
      return;
    }

    // If reduced motion is requested, render full text immediately with zero animation
    if (shouldReduceMotion) {
      setTypedText(authenticEvidenceText);
      setIsTypingComplete(true);
      return;
    }

    // Only run typewriter when a new investigation arrives
    if (prevSummaryIncidentRef.current === summary.incident_id) {
      setTypedText(authenticEvidenceText);
      setIsTypingComplete(true);
      return;
    }

    prevSummaryIncidentRef.current = summary.incident_id;
    setTypedText("");
    setIsTypingComplete(false);

    let currentIndex = 0;
    const totalLength = authenticEvidenceText.length;
    const intervalMs = 28;

    const timer = setInterval(() => {
      currentIndex += 2;
      if (currentIndex >= totalLength) {
        setTypedText(authenticEvidenceText);
        setIsTypingComplete(true);
        clearInterval(timer);
      } else {
        setTypedText(authenticEvidenceText.slice(0, currentIndex));
      }
    }, intervalMs);

    return () => {
      clearInterval(timer);
    };
  }, [summary, authenticEvidenceText, shouldReduceMotion]);

  // ── Scroll to primary investigation action helper ──
  const handleFocusPrimaryAction = () => {
    const btn = document.getElementById("run-triage-btn");
    if (btn) {
      btn.focus();
      btn.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  // Truthful node status computation
  const dbStatusText = isCompleted
    ? dbInfo
      ? dbInfo.db_name
      : "No forward path to restricted databases"
    : loading
    ? "Evaluating shortest paths…"
    : "Awaiting graph traversal";

  const dbSubText = isCompleted
    ? dbInfo && dbInfo.distance !== null && dbInfo.distance !== undefined
      ? dbInfo.distance === 0
        ? "Co-located on host (0 hops)"
        : `${dbInfo.distance} hop${dbInfo.distance === 1 ? "" : "s"} away (${dbInfo.classification || "RESTRICTED"})`
      : "No data layer path detected in 4-hop graph"
    : loading
    ? "GraphBLAS traversal in flight"
    : "High-value database evaluation pending";

  const brainStatusText = isCompleted
    ? brain?.team_name || "Owner not resolved"
    : loading
    ? "Querying Company Brain…"
    : "Team & Runbook SOP";

  const brainSubText = isCompleted
    ? brain?.person_name
      ? `Lead: ${brain.person_name} · SLA: ${brain.runbook_sla_minutes || 15}m`
      : brain?.team_name
      ? "Playbook SOP Assigned"
      : "Owner not resolved in Company Brain"
    : loading
    ? "Resolving team ownership…"
    : "Awaiting Company Brain lookup";

  return (
    <div
      aria-label="Investigation Journey Canvas"
      className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-4 sm:p-6 shadow-warm-xs relative overflow-hidden transition-all min-h-[340px] flex flex-col justify-between"
    >
      {/* ── Architectural Header & Diagnostics ── */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3.5 border-b border-[#EEE6DC]">
        <div className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center w-5 h-5">
            {loading ? (
              <span className="w-3.5 h-3.5 rounded-full border-2 border-[#D26A50] border-t-transparent animate-spin" />
            ) : isCompleted ? (
              <span className="w-2.5 h-2.5 rounded-full bg-[#26694E] shadow-sm" />
            ) : (
              <span className="w-2.5 h-2.5 rounded-full bg-[#82465D]" />
            )}
          </div>
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[#302B30]">
              Investigation Journey Canvas
            </h3>
            <p className="text-[11px] text-[#645C64] font-mono">
              {loading
                ? "FalkorDB GraphBLAS multi-hop query in flight…"
                : isCompleted
                ? `Autonomous query verified for incident ${activeIncidentId}`
                : "Continuous connected evaluation pipeline"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          {isCompleted ? (
            <>
              <span className="px-2.5 py-0.5 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0] font-semibold text-[11px] flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#26694E]" />
                <span>Verified Traversal</span>
              </span>
              <span className="text-[#82465D] bg-[#FAF7F2] border border-[#DFD6C9] px-2 py-0.5 rounded-md text-[11px] font-bold">
                {execTime.toFixed(1)}ms
              </span>
            </>
          ) : loading ? (
            <span className="px-2.5 py-0.5 rounded-full bg-[#FDF5E8] text-[#A06316] border border-[#F4DCB6] font-bold text-[11px] animate-pulse">
              Evaluating Propagation…
            </span>
          ) : (
            <span className="px-2.5 py-0.5 rounded-full bg-[#FAF7F2] text-[#645C64] border border-[#DFD6C9] text-[11px]">
              Status: Ready
            </span>
          )}

          <span
            className="hidden sm:inline-block text-[#928992] text-[11px]"
            title={resolvedTenant ? `Tenant ID: ${resolvedTenant}` : undefined}
          >
            Workspace: <strong className="text-[#645C64]">{organizationName || "Workspace"}</strong>
          </span>
        </div>
      </div>

      {/* ── Signature Continuous Flowing SVG Investigation Path (Desktop & Tablet) ── */}
      <div className="hidden md:block py-6 relative">
        {/* Continuous SVG Journey Geometry */}
        <div className="relative w-full h-36">
          <svg
            className="w-full h-full overflow-visible pointer-events-none"
            viewBox="0 0 1000 120"
            preserveAspectRatio="none"
          >
            <defs>
              {/* Active Path Gradient */}
              <linearGradient id="journey-path-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#D26A50" />
                <stop offset="33%" stopColor="#C24128" />
                <stop offset="66%" stopColor="#E6A548" />
                <stop offset="100%" stopColor="#82465D" />
              </linearGradient>

              {/* Inactive Path Gradient */}
              <linearGradient id="journey-path-inactive" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#E0D6C8" />
                <stop offset="100%" stopColor="#E8E0D5" />
              </linearGradient>
            </defs>

            {/* Base Continuous Architectural Route */}
            <path
              d="M 125 60 C 240 25, 260 95, 375 60 C 490 25, 510 95, 625 60 C 740 25, 760 95, 875 60"
              fill="none"
              stroke="url(#journey-path-inactive)"
              strokeWidth="3"
              strokeDasharray="4 6"
            />

            {/* Active Connected Highway */}
            {(isCompleted || loading) && (
              <path
                d="M 125 60 C 240 25, 260 95, 375 60 C 490 25, 510 95, 625 60 C 740 25, 760 95, 875 60"
                fill="none"
                stroke="url(#journey-path-gradient)"
                strokeWidth={isCompleted ? "3.5" : "2.5"}
                strokeDasharray={loading ? "8 6" : "none"}
                className={loading ? "animate-pulse" : ""}
                style={{
                  filter: isCompleted ? "drop-shadow(0 1px 3px rgba(210,106,80,0.25))" : "none",
                }}
              />
            )}

            {/* Mid-flight Directional Markers */}
            <circle cx="250" cy="60" r="3" fill="#D26A50" fillOpacity={isCompleted ? 0.8 : 0.25} />
            <circle cx="500" cy="60" r="3" fill="#E6A548" fillOpacity={isCompleted ? 0.8 : 0.25} />
            <circle cx="750" cy="60" r="3" fill="#82465D" fillOpacity={isCompleted ? 0.8 : 0.25} />
          </svg>

          {/* HTML Overlay: 4 Distinct Stations positioned precisely above the SVG path */}
          <div className="absolute inset-0 grid grid-cols-4 gap-4 items-center">
            {/* Station 01: ORIGIN ASSET */}
            <div className="flex flex-col items-center text-center px-2">
              <div className="relative mb-2">
                <div
                  className="w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs text-white shadow-warm-xs z-10 relative"
                  style={{ backgroundColor: "#D26A50" }}
                >
                  01
                </div>
                {/* Focal ring for Origin Asset */}
                <div
                  className="absolute -inset-1 rounded-full border border-[#D26A50]/40 animate-pulse pointer-events-none"
                  aria-hidden="true"
                />
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#D26A50] font-bold">
                ORIGIN ASSET
              </div>
              <div className="text-xs font-bold text-[#302B30] truncate max-w-full mt-0.5" title={selectedAsset?.name}>
                {selectedAsset ? selectedAsset.name : "Select Asset"}
              </div>
              <div className="text-[11px] font-mono text-[#645C64] truncate max-w-full">
                {selectedAsset ? `${selectedAsset.id} · ${selectedAsset.ip}` : "Awaiting selection"}
              </div>
            </div>

            {/* Station 02: LATERAL EXPOSURE */}
            <div className="flex flex-col items-center text-center px-2">
              <div className="relative mb-2">
                <div
                  className="w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs shadow-warm-xs z-10 relative transition-colors"
                  style={{
                    backgroundColor: isCompleted ? "#C24128" : loading ? "#FDF5E8" : "#FAF7F2",
                    color: isCompleted ? "#FFFFFF" : isCompleted || loading ? "#A06316" : "#928992",
                    border: `2px solid ${isCompleted ? "#C24128" : isCompleted || loading ? "#F4DCB6" : "#DFD6C9"}`,
                  }}
                >
                  02
                </div>
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#C24128] font-bold">
                LATERAL EXPOSURE
              </div>
              <div className="text-xs font-bold text-[#302B30] truncate max-w-full mt-0.5">
                {isCompleted
                  ? `${targetCount} Lateral Vector${targetCount === 1 ? "" : "s"}`
                  : loading
                  ? "Evaluating Propagation…"
                  : "Lateral Propagation"}
              </div>
              <div className="text-[11px] font-mono text-[#645C64] truncate max-w-full">
                {isCompleted
                  ? `${targetCount} reachable host(s) evaluated`
                  : loading
                  ? "GraphBLAS traversal in flight"
                  : "Awaiting graph traversal"}
              </div>
            </div>

            {/* Station 03: DATA PROXIMITY */}
            <div className="flex flex-col items-center text-center px-2">
              <div className="relative mb-2">
                <div
                  className="w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs shadow-warm-xs z-10 relative transition-colors"
                  style={{
                    backgroundColor: isCompleted && dbInfo ? "#E6A548" : isCompleted ? "#E8F2EC" : loading ? "#FDF5E8" : "#FAF7F2",
                    color: isCompleted && dbInfo ? "#FFFFFF" : isCompleted ? "#26694E" : isCompleted || loading ? "#A06316" : "#928992",
                    border: `2px solid ${isCompleted && dbInfo ? "#E6A548" : isCompleted ? "#C5DFD0" : isCompleted || loading ? "#F4DCB6" : "#DFD6C9"}`,
                  }}
                >
                  03
                </div>
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#A06316] font-bold">
                DATA PROXIMITY
              </div>
              <div className="text-xs font-bold text-[#302B30] truncate max-w-full mt-0.5" title={dbStatusText}>
                {dbStatusText}
              </div>
              <div className="text-[11px] font-mono text-[#645C64] truncate max-w-full" title={dbSubText}>
                {dbSubText}
              </div>
            </div>

            {/* Station 04: GOVERNANCE GATEWAY */}
            <div className="flex flex-col items-center text-center px-2">
              <div className="relative mb-2">
                <div
                  className="w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs shadow-warm-xs z-10 relative transition-colors"
                  style={{
                    backgroundColor: isCompleted && brain?.team_name ? "#82465D" : isCompleted ? "#FAF7F2" : loading ? "#FDF5E8" : "#FAF7F2",
                    color: isCompleted && brain?.team_name ? "#FFFFFF" : isCompleted ? "#82465D" : isCompleted || loading ? "#A06316" : "#928992",
                    border: `2px solid ${isCompleted && brain?.team_name ? "#82465D" : isCompleted ? "#E5CDD8" : isCompleted || loading ? "#F4DCB6" : "#DFD6C9"}`,
                  }}
                >
                  04
                </div>
              </div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#82465D] font-bold">
                GOVERNANCE GATEWAY
              </div>
              <div className="text-xs font-bold text-[#302B30] truncate max-w-full mt-0.5" title={brainStatusText}>
                {brainStatusText}
              </div>
              <div className="text-[11px] font-mono text-[#645C64] truncate max-w-full" title={brainSubText}>
                {brainSubText}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Mobile Vertical Flowing Investigation Path (< md) ── */}
      <div className="md:hidden py-3 space-y-3 relative">
        {/* Vertical SVG Spine */}
        <div className="absolute left-[19px] top-6 bottom-6 w-[2px] bg-[#E8E0D5]" aria-hidden="true" />

        {/* Station 01 Mobile */}
        <div className="flex items-start gap-3 relative">
          <div className="w-10 h-10 rounded-full bg-[#D26A50] text-white flex items-center justify-center font-mono font-bold text-xs shrink-0 z-10 shadow-warm-xs">
            01
          </div>
          <div className="flex-1 min-w-0 pt-0.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#D26A50] font-bold">
              ORIGIN ASSET
            </div>
            <div className="text-xs font-bold text-[#302B30] truncate">
              {selectedAsset ? selectedAsset.name : "Select Asset"}
            </div>
            <div className="text-[11px] font-mono text-[#645C64] truncate">
              {selectedAsset ? `${selectedAsset.id} · ${selectedAsset.ip}` : "Awaiting selection"}
            </div>
          </div>
        </div>

        {/* Station 02 Mobile */}
        <div className="flex items-start gap-3 relative">
          <div
            className={`w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs shrink-0 z-10 shadow-warm-xs border ${
              isCompleted
                ? "bg-[#C24128] text-white border-[#C24128]"
                : loading
                ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]"
                : "bg-[#FAF7F2] text-[#928992] border-[#DFD6C9]"
            }`}
          >
            02
          </div>
          <div className="flex-1 min-w-0 pt-0.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#C24128] font-bold">
              LATERAL EXPOSURE
            </div>
            <div className="text-xs font-bold text-[#302B30] truncate">
              {isCompleted
                ? `${targetCount} Lateral Vector${targetCount === 1 ? "" : "s"}`
                : loading
                ? "Evaluating Propagation…"
                : "Lateral Propagation"}
            </div>
            <div className="text-[11px] font-mono text-[#645C64] truncate">
              {isCompleted
                ? `${targetCount} reachable host(s) evaluated`
                : loading
                ? "GraphBLAS traversal in flight"
                : "Awaiting graph traversal"}
            </div>
          </div>
        </div>

        {/* Station 03 Mobile */}
        <div className="flex items-start gap-3 relative">
          <div
            className={`w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs shrink-0 z-10 shadow-warm-xs border ${
              isCompleted && dbInfo
                ? "bg-[#E6A548] text-white border-[#E6A548]"
                : isCompleted
                ? "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]"
                : loading
                ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]"
                : "bg-[#FAF7F2] text-[#928992] border-[#DFD6C9]"
            }`}
          >
            03
          </div>
          <div className="flex-1 min-w-0 pt-0.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#A06316] font-bold">
              DATA PROXIMITY
            </div>
            <div className="text-xs font-bold text-[#302B30] truncate">
              {dbStatusText}
            </div>
            <div className="text-[11px] font-mono text-[#645C64] truncate">
              {dbSubText}
            </div>
          </div>
        </div>

        {/* Station 04 Mobile */}
        <div className="flex items-start gap-3 relative">
          <div
            className={`w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold text-xs shrink-0 z-10 shadow-warm-xs border ${
              isCompleted && brain?.team_name
                ? "bg-[#82465D] text-white border-[#82465D]"
                : isCompleted
                ? "bg-[#FAF7F2] text-[#82465D] border-[#E5CDD8]"
                : loading
                ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]"
                : "bg-[#FAF7F2] text-[#928992] border-[#DFD6C9]"
            }`}
          >
            04
          </div>
          <div className="flex-1 min-w-0 pt-0.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#82465D] font-bold">
              GOVERNANCE GATEWAY
            </div>
            <div className="text-xs font-bold text-[#302B30] truncate">
              {brainStatusText}
            </div>
            <div className="text-[11px] font-mono text-[#645C64] truncate">
              {brainSubText}
            </div>
          </div>
        </div>
      </div>

      {/* ── Auto-Completion Evidence Reveal Interaction (Requirement 5) ── */}
      {isCompleted && (
        <div className="my-2 p-3 rounded-xl bg-[#FAF7F2] border border-[#EEE6DC] space-y-1.5">
          <div className="flex items-center justify-between text-[10px] font-mono text-[#82465D]">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#D26A50]" />
              <span className="font-bold uppercase tracking-wider">Verified Graph Evidence Sequence</span>
            </div>
            <span className="text-[#928992]">FalkorDB GraphBLAS</span>
          </div>

          <div className="font-mono text-xs text-[#302B30] leading-relaxed break-words min-h-[36px]">
            <span className="text-[#D26A50] font-bold mr-1">&gt;</span>
            <span>{typedText}</span>
            {!isTypingComplete && !shouldReduceMotion && (
              <span className="inline-block w-1.5 h-3 bg-[#D26A50] ml-0.5 animate-pulse align-middle" />
            )}
          </div>
        </div>
      )}

      {/* ── Read-Only Contextual Navigation Strip (Requirement 6: No duplicate button) ── */}
      <div className="pt-3 border-t border-[#EEE6DC] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono text-[#645C64]">
        <div className="flex items-center gap-2">
          <span className="text-[11px]">
            Selected Target: <strong className="text-[#302B30]">{selectedAsset?.name || "None"}</strong>{" "}
            ({selectedAsset?.id || "—"})
          </span>
          {isCompleted && (
            <span className="text-[#82465D] hidden lg:inline">
              · Perimeter Egress: <strong className="font-bold">{egressRisk} Mbps</strong>
            </span>
          )}
        </div>

        {!isCompleted && !loading ? (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-[#645C64]">
              Ready to evaluate target ·
            </span>
            <button
              type="button"
              onClick={handleFocusPrimaryAction}
              className="text-[11px] text-[#D26A50] hover:text-[#BE5B42] hover:underline font-bold inline-flex items-center gap-1 cursor-pointer"
            >
              <span>Investigation Action</span>
              <span>↑</span>
            </button>
          </div>
        ) : isCompleted ? (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-[#26694E] font-semibold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#26694E]" />
              <span>Findings assembled · Ready for Incident Triage Deck review →</span>
            </span>
          </div>
        ) : (
          <div className="text-[11px] text-[#A06316] font-medium flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#A06316] animate-pulse" />
            <span>Processing variable-length traversal paths…</span>
          </div>
        )}
      </div>
    </div>
  );
};
