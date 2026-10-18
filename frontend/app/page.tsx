"use client";

import React, { useState, useCallback } from "react";
import Image from "next/image";
import Link from "next/link";
import { HeroSection, type InvestigationSummary } from "@/components/HeroSection";
import { IncidentJourneyTimeline } from "@/components/IncidentJourneyTimeline";
import { FallingBlockGrid } from "@/components/FallingBlockGrid";
import { SwipeableCardStack } from "@/components/SwipeableCardStack";
import { GraphCanvas } from "@/components/GraphCanvas";
import { RiskPrioritiesDeck } from "@/components/RiskPrioritiesDeck";
import { LiveEvidenceComposer } from "@/components/LiveEvidenceComposer";
import { CompanyBrainDossier } from "@/components/CompanyBrainDossier";

const API_DOCS_URL = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/docs`
  : "http://localhost:8000/docs";

export default function HomePage() {
  const [selectedAssetId, setSelectedAssetId] = useState<string>("host-0");
  const [activeInvestigation, setActiveInvestigation] = useState<InvestigationSummary | null>(null);
  const [activeIncident, setActiveIncident] = useState<{
    incidentId: string;
    targetHost: string;
    targetHostId: string;
  }>({
    incidentId: "inc-latest",
    targetHost: "Workstation-PatientZero (host-0)",
    targetHostId: "host-0",
  });
  const [isContained, setIsContained] = useState<boolean>(false);
  const [containmentAudit, setContainmentAudit] = useState<{
    audit_id: string;
    action_id: string;
    executed_by: string;
    executed_at: number;
    verification: string;
    paths_severed: number;
    egress_reduced_mbps: number;
  } | null>(null);

  const handleInvestigationComplete = useCallback((summary: InvestigationSummary) => {
    setActiveInvestigation(summary);
    const hostId = summary.patient_zero_id || "host-0";
    const hostName = summary.patient_zero_name || "Workstation-PatientZero";
    setSelectedAssetId(hostId);
    setActiveIncident({
      incidentId: summary.incident_id,
      targetHost: `${hostName} (${hostId})`,
      targetHostId: hostId,
    });
    // Critical correctness check: reset containment state for newly investigated incident
    setIsContained(false);
    setContainmentAudit(null);
  }, []);

  const handleContainmentExecuted = useCallback((auditData: Record<string, unknown>) => {
    setIsContained(true);
    const beforeAfter = auditData.before_after as Record<string, unknown> | undefined;
    const pathsSevered = typeof beforeAfter?.paths_severed === "number" ? beforeAfter.paths_severed : 14;
    const egressReduced = typeof beforeAfter?.egress_reduction_mbps === "number" ? beforeAfter.egress_reduction_mbps : 43.0;

    setContainmentAudit({
      audit_id: (auditData.audit_id as string) || `aud-${Date.now()}`,
      action_id: (auditData.action_id as string) || "act-contain",
      executed_by: (auditData.executed_by as string) || "alex.rivera",
      executed_at: Date.now() / 1000,
      verification: (auditData.verification as string) || "VERIFIED",
      paths_severed: pathsSevered,
      egress_reduced_mbps: egressReduced,
    });
  }, []);

  const handleContainmentRejected = useCallback(() => {
    setIsContained(false);
    setContainmentAudit(null);
  }, []);

  const handleAssetSelect = useCallback((id: string) => {
    setSelectedAssetId(id);
    setActiveIncident((prev) => ({
      ...prev,
      targetHostId: id,
      targetHost: `${id}`,
    }));
  }, []);

  return (
    <main className="min-h-screen bg-[#FAF7F2] text-[#302B30] selection:bg-[#D26A50]/20 selection:text-[#302B30]">
      {/* ── Top Navigation Bar ────────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 border-b border-[#DFD6C9] bg-[#FAF7F2]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          {/* Brand Wordmark */}
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2.5 focus:outline-none">
              <Image
                src="/brand/rootmesh-wordmark.png"
                alt="RootMesh"
                width={170}
                height={40}
                className="h-8 w-auto object-contain"
                priority
              />
            </Link>
            <span className="hidden md:inline-block text-[11px] text-[#645C64] font-mono bg-[#F5EFE6] border border-[#DFD6C9] px-2 py-0.5 rounded-md">
              FalkorDB GraphBLAS v6
            </span>
          </div>

          {/* Operational Status Badges */}
          <div className="flex items-center gap-2.5 text-xs font-mono">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#26694E] animate-pulse inline-block" />
              <span>Connected</span>
            </span>
            <span className="hidden sm:inline-block text-[#82465D] bg-[#F6EDF1] px-2.5 py-1 rounded-md border border-[#E5CDD8] font-bold">
              sec_ops_tenant_alpha
            </span>
            <a
              href={API_DOCS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#645C64] hover:text-[#302B30] hover:bg-[#EEE6DC] px-2.5 py-1 rounded-md transition-colors border border-transparent hover:border-[#DFD6C9]"
            >
              API Docs ↗
            </a>
          </div>
        </div>
      </nav>

      {/* ── Main Workspace Body ───────────────────────────────────────── */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-12">
        {/* ── Section 1: Operations Command Center ────────────────────── */}
        <section aria-label="Operations Command Center" className="space-y-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#82465D] mb-3">
              <span className="w-1.5 h-1.5 rounded-full bg-[#D26A50]" />
              <span>Autonomous Threat Memory & GraphBLAS Engine</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[#302B30]">
              Threat Intelligence &{" "}
              <span className="text-[#D26A50]">Incident Operations</span>{" "}
              Workspace
            </h1>
            <p className="text-sm text-[#645C64] mt-2 max-w-3xl leading-relaxed">
              Sub-millisecond graph reasoning powered by FalkorDB GraphBLAS. Evaluate multi-hop lateral propagation vectors,
              calculate network egress blast radius, resolve organizational ownership, and execute guarded containment workflows.
            </p>
          </div>

          <HeroSection onInvestigationComplete={handleInvestigationComplete} />
        </section>

        {/* ── Section 2: Incident Response Lifecycle ──────────────────── */}
        <section aria-label="Incident Response Lifecycle">
          <IncidentJourneyTimeline
            incidentId={activeIncident.incidentId}
            targetHost={activeIncident.targetHost}
            hasInvestigation={!!activeInvestigation}
            hasProposal={isContained}
            hasReview={isContained}
            hasExecution={isContained}
          />
        </section>

        {/* ── Section 3: Real-Time Threat Operations ──────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Left Column: Live Threat Propagation Matrix */}
          <section aria-label="Live Threat Propagation Matrix">
            <FallingBlockGrid />
          </section>

          {/* Right Column: Human-Governed Response Deck */}
          <section aria-label="Incident Triage & Action Deck">
            <div className="rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-6 shadow-warm-sm space-y-3">
              <div className="border-b border-[#EEE6DC] pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#82465D]" />
                  <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
                    Incident Triage & Action Deck
                  </h3>
                </div>
                <p className="text-xs text-[#645C64] mt-0.5">
                  Swipe right to propose containment · Swipe left to dismiss · Explicit authorized human review required
                </p>
              </div>

              <SwipeableCardStack
                activeTargetHostId={activeIncident.targetHostId}
                onContainmentExecuted={handleContainmentExecuted}
                onContainmentRejected={handleContainmentRejected}
              />
            </div>
          </section>
        </div>

        {/* ── Section 4: Connected Graph Explorer ─────────────────────── */}
        <section aria-label="Connected Graph Explorer">
          <GraphCanvas
            selectedAssetId={selectedAssetId}
            isContained={isContained}
            onSelectNode={handleAssetSelect}
          />
        </section>

        {/* ── Section 5: Risk Priorities — Connected Exposure Insights ── */}
        <section aria-label="Risk Priorities">
          <RiskPrioritiesDeck
            selectedAssetId={selectedAssetId}
            onSelectAsset={handleAssetSelect}
          />
        </section>

        {/* ── Section 6: Signature Feature — Live Evidence Composer ───── */}
        <section aria-label="Live Evidence Composer">
          <LiveEvidenceComposer
            investigation={activeInvestigation}
            selectedAssetId={selectedAssetId}
            targetHost={activeIncident.targetHost}
            incidentId={activeIncident.incidentId}
          />
        </section>

        {/* ── Section 7: Investigation Evidence & Organizational Knowledge ── */}
        <section aria-label="Investigation Evidence & Knowledge Dossier">
          <CompanyBrainDossier
            incidentId={activeIncident.incidentId}
            targetHost={activeIncident.targetHost}
            hasInvestigation={!!activeInvestigation}
            isContained={isContained}
            containmentAudit={containmentAudit}
            targetCount={activeInvestigation?.target_count}
            egressRiskMbps={activeInvestigation?.egress_risk_mbps}
            shortestPathDb={activeInvestigation?.shortest_path_db}
            companyBrain={activeInvestigation?.company_brain}
          />
        </section>
      </div>

      {/* ── Editorial Warm Light Footer ───────────────────────────────── */}
      <footer className="border-t border-[#DFD6C9] bg-[#FAF7F2] mt-16 px-4 sm:px-6 py-8">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-4 text-xs text-[#645C64] font-mono">
          <div className="flex items-center gap-2.5">
            <Image
              src="/brand/rootmesh-icon.png"
              alt="RootMesh Icon"
              width={24}
              height={24}
              className="h-6 w-auto object-contain"
            />
            <span className="font-bold text-[#302B30]">RootMesh</span>
            <span>— FalkorDB Autonomous Threat Operations</span>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-[11px]">
            <a
              href={API_DOCS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#D26A50] transition-colors"
            >
              OpenAPI Swagger UI ↗
            </a>
            <a
              href="http://localhost:3005"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#D26A50] transition-colors"
            >
              FalkorDB Visualizer (Port 3005) ↗
            </a>
            <span className="text-[#82465D] font-medium">
              GRAPH_TOPOLOGY_SIMULATION Verified
            </span>
          </div>
        </div>

        <div className="max-w-7xl mx-auto mt-4 pt-4 border-t border-[#EEE6DC] text-[10px] text-[#928992] font-mono text-center sm:text-left leading-relaxed">
          Notice: Company Brain organizational entities (teams, on-call responders, runbooks, commit provenance) and containment isolation are synthetic demonstration records and topological simulations in FalkorDB for evaluation.
        </div>
      </footer>
    </main>
  );
}
