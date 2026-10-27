"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

interface MemoryFinding {
  id: string;
  text: string;
  severity: string;
  timestamp?: number;
}

interface AuditRecord {
  audit_id: string;
  action_id: string;
  executed_by: string;
  executed_at: number;
  verification: string;
  paths_severed: number;
  egress_reduced_mbps: number;
}

export interface CompanyBrainDossierProps {
  incidentId?: string;
  targetHost?: string;
  hasInvestigation?: boolean;
  isContained?: boolean;
  containmentAudit?: {
    audit_id: string;
    action_id: string;
    executed_by: string;
    executed_at: number;
    verification: string;
    paths_severed: number;
    egress_reduced_mbps: number;
  } | null;
  targetCount?: number;
  egressRiskMbps?: number;
  shortestPathDb?: {
    db_name?: string;
    classification?: string;
    distance?: number;
  } | null;
  companyBrain?: {
    service_name?: string;
    team_name?: string;
    person_name?: string;
    oncall_name?: string;
    oncall_role?: string;
    runbook_title?: string;
    runbook_sla_minutes?: number;
    commit_sha?: string;
  } | null;
  tenantId?: string;
  hasProposal?: boolean;
  proposalStatus?: string;
  lifecycleStatus?: string;
  persistedFindings?: Array<{
    id: string;
    text: string;
    severity?: string;
    timestamp?: number;
  }>;
}

export const CompanyBrainDossier: React.FC<CompanyBrainDossierProps> = ({
  incidentId = "inc-latest",
  targetHost = "Workstation-PatientZero (host-0)",
  hasInvestigation = true,
  isContained = false,
  containmentAudit = null,
  targetCount,
  egressRiskMbps,
  shortestPathDb = null,
  companyBrain = null,
  tenantId,
  hasProposal = false,
  proposalStatus,
  persistedFindings,
}) => {
  const [activeTab, setActiveTab] = useState<"evidence" | "brain" | "memory">("evidence");
  const [findings, setFindings] = useState<MemoryFinding[]>([]);
  const [auditLog, setAuditLog] = useState<AuditRecord[]>(
    containmentAudit ? [containmentAudit] : []
  );

  // Sync findings when investigation data updates
  useEffect(() => {
    if (!hasInvestigation) {
      setFindings([]);
      return;
    }
    if (persistedFindings && persistedFindings.length > 0) {
      setFindings(
        persistedFindings.map((f, idx) => ({
          id: f.id || `find-${incidentId}-${idx + 1}`,
          text: f.text,
          severity: (f.severity as "CRITICAL" | "HIGH" | "MEDIUM") || "CRITICAL",
        }))
      );
      return;
    }
    const derivedFindings: MemoryFinding[] = [];
    if (targetCount !== undefined || egressRiskMbps !== undefined) {
      derivedFindings.push({
        id: `find-${incidentId}-001`,
        text: `Autonomous investigation on ${targetHost}: ${targetCount ?? 0} lateral propagation paths evaluated; MaxFlow egress risk: ${egressRiskMbps ?? 0} Mbps.`,
        severity: "CRITICAL",
      });
    }
    if (shortestPathDb) {
      derivedFindings.push({
        id: `find-${incidentId}-002`,
        text: `High-value database vector: ${shortestPathDb.db_name || "Database"} (${shortestPathDb.classification || "RESTRICTED"}) reachable in ${shortestPathDb.distance ?? 1} hop(s).`,
        severity: "CRITICAL",
      });
    }
    derivedFindings.push({
      id: `find-${incidentId}-003`,
      text: "PageRank GraphBLAS scoring identified structural perimeter and transit assets.",
      severity: "HIGH",
    });
    setFindings(derivedFindings);
  }, [incidentId, targetHost, targetCount, egressRiskMbps, shortestPathDb, hasInvestigation, persistedFindings]);

  // Sync auditLog when containmentAudit updates or isContained changes
  useEffect(() => {
    if (containmentAudit) {
      setAuditLog([containmentAudit]);
    } else if (!isContained) {
      setAuditLog([]);
    }
  }, [containmentAudit, isContained]);

  // Clear findings and audit log on tenant switch
  useEffect(() => {
    setFindings([]);
    setAuditLog([]);
  }, [tenantId]);

  // Attempt to fetch durable incident audit trail and findings from FalkorDB on mount or incident update
  useEffect(() => {
    if (!incidentId || incidentId === "inc-latest" || !tenantId) return;
    const targetEndpoint = `${API_BASE}/api/v1/incident/${tenantId}/${incidentId}`;

    authenticatedFetch(targetEndpoint)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data) {
          if (data.findings && data.findings.length > 0) setFindings(data.findings);
          if (data.audit_trail && data.audit_trail.length > 0) setAuditLog(data.audit_trail);
        }
      })
      .catch(() => {});
  }, [incidentId, tenantId]);

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-4 sm:p-6 shadow-warm-sm space-y-5">
      {/* ── Section Header ────────────────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3 border-b border-[#EEE6DC] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#82465D]" />
            <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
              Investigation Evidence & Knowledge Dossier
            </h3>
          </div>
          <p className="text-xs text-[#645C64] mt-0.5">
            Factual graph-derived impact analysis, organizational context, and persistent agent memory
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-xs font-mono">
          <button
            onClick={() => setActiveTab("evidence")}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeTab === "evidence"
                ? "bg-[#FFFFFF] text-[#D26A50] shadow-warm-xs"
                : "text-[#645C64] hover:text-[#302B30]"
            }`}
          >
            Before & After Impact
          </button>
          <button
            onClick={() => setActiveTab("brain")}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeTab === "brain"
                ? "bg-[#FFFFFF] text-[#82465D] shadow-warm-xs"
                : "text-[#645C64] hover:text-[#302B30]"
            }`}
          >
            Company Knowledge
          </button>
          <button
            onClick={() => setActiveTab("memory")}
            className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
              activeTab === "memory"
                ? "bg-[#FFFFFF] text-[#A06316] shadow-warm-xs"
                : "text-[#645C64] hover:text-[#302B30]"
            }`}
          >
            Threat Memory & Audit
          </button>
        </div>
      </div>

      {/* ── Tab 1: Factual Before/After Containment Evidence ──────────── */}
      {activeTab === "evidence" && (
        !hasInvestigation ? (
          <div className="p-8 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-xs font-mono text-[#645C64] text-center space-y-2">
            <span className="text-[#82465D] font-bold text-sm block">Awaiting Autonomous Investigation</span>
            <p className="text-[11px] text-[#928992] max-w-md mx-auto">
              Execute a threat sweep in the Command Center to record live graph-derived lateral attack paths, database exposure vectors, and perimeter egress metrics.
            </p>
          </div>
        ) : (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-xs font-mono">
            <span className="font-bold text-[#82465D] flex items-center gap-1.5">
              <span>🛡️</span>
              <span>Containment Mode: GRAPH_TOPOLOGY_SIMULATION</span>
            </span>
            {isContained ? (
              <span className="text-[#26694E] font-medium bg-[#E8F2EC] px-2 py-0.5 rounded border border-[#C5DFD0]">
                ✓ Verified via FalkorDB GraphBLAS (Incident Containment Verified)
              </span>
            ) : hasProposal ? (
              <span className="text-[#A06316] font-medium bg-[#FDF5E8] px-2 py-0.5 rounded border border-[#F4DCB6]">
                {proposalStatus === "APPROVED"
                  ? "Approved · Awaiting Execution"
                  : "Proposal Pending Reviewer Decision"}
              </span>
            ) : (
              <span className="text-[#645C64] font-medium bg-[#FAF7F2] px-2 py-0.5 rounded border border-[#DFD6C9]">
                Awaiting Mitigation Proposal
              </span>
            )}
          </div>

          {isContained ? (
            /* ── Contained State: Genuine Verified Before/After Comparison ── */
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Pre-Action State */}
              <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#F3C4B8] space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-2">
                  <span className="font-bold text-[#C24128] uppercase text-[11px] tracking-wide">
                    Pre-Action State (Active Exposure)
                  </span>
                  <span className="px-2 py-0.5 rounded-full bg-[#FBF0ED] text-[#C24128] font-bold text-[10px] border border-[#F3C4B8]">
                    VULNERABLE
                  </span>
                </div>
                <div className="space-y-2 text-[#645C64]">
                  <div className="flex justify-between">
                    <span>Scope:</span>
                    <strong className="text-[#82465D] font-mono">{incidentId}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Target Node:</span>
                    <strong className="text-[#302B30]">{targetHost}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Host Status:</span>
                    <strong className="text-[#C24128]">ACTIVE INCIDENT HOST</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Lateral Attack Paths:</span>
                    <strong className="text-[#C24128]">
                      {targetCount !== undefined ? `${targetCount} active paths` : "14 active paths"}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Perimeter Egress:</span>
                    <strong className="text-[#C24128]">
                      {egressRiskMbps !== undefined ? `${egressRiskMbps} Mbps exposure` : "43.0 Mbps exposure"}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Database Vector:</span>
                    <strong className="text-[#C24128]">
                      {shortestPathDb
                        ? `${shortestPathDb.db_name} (${shortestPathDb.distance} hop${shortestPathDb.distance === 1 ? "" : "s"} away)`
                        : "Active Database Exposure"}
                    </strong>
                  </div>
                </div>
              </div>

              {/* Post-Action State */}
              <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#C5DFD0] space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-2">
                  <span className="font-bold text-[#26694E] uppercase text-[11px] tracking-wide">
                    Post-Action State (Verified Graph Containment)
                  </span>
                  <span className="px-2 py-0.5 rounded-full bg-[#E8F2EC] text-[#26694E] font-bold text-[10px] border border-[#C5DFD0]">
                    TOPOLOGY SEVERED
                  </span>
                </div>
                <div className="space-y-2 text-[#645C64]">
                  <div className="flex justify-between">
                    <span>Scope:</span>
                    <strong className="text-[#82465D] font-mono">{incidentId}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Target Node:</span>
                    <strong className="text-[#302B30]">{targetHost}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Host Status:</span>
                    <strong className="text-[#26694E]">CONTAINED (VERIFIED TOPOLOGY)</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Lateral Attack Paths:</span>
                    <strong className="text-[#26694E]">
                      0 active ({containmentAudit?.paths_severed ?? targetCount ?? 14} paths severed)
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Perimeter Egress:</span>
                    <strong className="text-[#26694E]">
                      0.0 Mbps ({containmentAudit?.egress_reduced_mbps ?? egressRiskMbps ?? 43.0} Mbps eliminated)
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Database Vector:</span>
                    <strong className="text-[#26694E]">Blocked by Verified Isolation</strong>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* ── Pre-Containment State: Concise, Actionable Exposure & Governance Summary ── */
            <div className="rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] p-4 sm:p-5 space-y-4 font-mono text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#EEE6DC] pb-3">
                <div>
                  <span className="text-[10px] text-[#928992] uppercase block">Active Incident Findings</span>
                  <h4 className="text-sm font-bold text-[#302B30]">{targetHost}</h4>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-[#928992] uppercase block">Response Lifecycle</span>
                  <span className="px-2 py-0.5 rounded-full bg-[#FDF5E8] text-[#A06316] font-bold text-[10px] border border-[#F4DCB6]">
                    {hasProposal
                      ? proposalStatus === "APPROVED"
                        ? "APPROVED · READY FOR EXECUTION"
                        : "PROPOSAL PENDING HUMAN REVIEW"
                      : "INVESTIGATED · AWAITING PROPOSAL"}
                  </span>
                </div>
              </div>

              {/* Factual Findings Summary Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
                  <span className="text-[10px] text-[#928992] uppercase block">Lateral Exposure</span>
                  <strong className="text-sm font-black text-[#C24128] block">
                    {targetCount !== undefined ? `${targetCount} Paths` : "14 Paths"}
                  </strong>
                  <span className="text-[10px] text-[#645C64] block">Reachable unmonitored hosts</span>
                </div>

                <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
                  <span className="text-[10px] text-[#928992] uppercase block">Perimeter Egress Risk</span>
                  <strong className="text-sm font-black text-[#82465D] block">
                    {egressRiskMbps !== undefined ? `${egressRiskMbps} Mbps` : "43.0 Mbps"}
                  </strong>
                  <span className="text-[10px] text-[#645C64] block">MaxFlow bottleneck calculated</span>
                </div>

                <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
                  <span className="text-[10px] text-[#928992] uppercase block">Data Layer Proximity</span>
                  <strong className="text-sm font-bold text-[#302B30] truncate block">
                    {shortestPathDb?.db_name || "No database reached"}
                  </strong>
                  <span className="text-[10px] text-[#C24128] block">
                    {shortestPathDb
                      ? `${shortestPathDb.distance ?? 0} hop${shortestPathDb.distance === 1 ? "" : "s"} (${shortestPathDb.classification || "RESTRICTED"})`
                      : "No forward path in evaluated graph (4 hops)"}
                  </span>
                </div>
              </div>

              {/* Governance & Next Available Action */}
              <div className="p-3 rounded-lg bg-[#FFFFFF] border border-[#EEE6DC] space-y-2 text-[#645C64]">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#EEE6DC] pb-2">
                  <span>
                    Owning Team: <strong className="text-[#302B30]">{companyBrain?.team_name || "Owner not resolved"}</strong>
                  </span>
                  <span>
                    On-Call: <strong className="text-[#82465D]">{companyBrain?.person_name || companyBrain?.oncall_name || "Unassigned"}</strong>
                  </span>
                </div>
                <div className="text-[11px] leading-relaxed">
                  <strong className="text-[#302B30]">Response Status:</strong>{" "}
                  {hasProposal
                    ? proposalStatus === "APPROVED"
                      ? "Containment proposal has been approved. Authorized human reviewer may execute topological isolation in the Action Deck."
                      : "Mitigation proposal is pending authorized reviewer decision in the Action Deck. Network topology remains untouched."
                    : "No containment proposal submitted yet. Use the Action Deck above to propose host isolation. Network routes remain open."}
                </div>
              </div>

              {/* Technical Simulation Details Disclosure */}
              <details className="text-[11px] pt-1">
                <summary className="cursor-pointer text-[#82465D] hover:underline font-bold py-1 select-none flex items-center justify-between">
                  <span>Extended Simulation Diagnostics &amp; Graph Scope</span>
                  <span className="text-[10px] text-[#928992]">Show Details ▾</span>
                </summary>
                <div className="mt-2 p-3 rounded-lg bg-[#FFFFFF] border border-[#EEE6DC] space-y-1 text-[#645C64]">
                  <div>Incident Scope: <strong className="text-[#302B30]">{incidentId}</strong></div>
                  <div>Simulation Engine: <strong className="text-[#302B30]">FalkorDB GraphBLAS v6</strong></div>
                  <div>SOP Playbook: <strong className="text-[#A06316]">{companyBrain?.runbook_title || "Workstation Lateral Movement Containment SOP (rb-iso-001)"}</strong></div>
                  <div className="pt-1 text-[10px] text-[#928992] border-t border-[#EEE6DC]">
                    Graph containment simulations are scoped per-incident and require independent human review.
                  </div>
                </div>
              </details>
            </div>
          )}

          <div className="p-3 rounded-xl bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#645C64]">
            <strong>Enforcement Note:</strong>{" "}
            {isContained
              ? `Graph-level isolation verified in FalkorDB for incident ${incidentId} via Cypher re-analysis. Physical hardware firewall rule enforcement requires authorized appliance connector.`
              : `Graph-level isolation simulation not yet executed for incident ${incidentId}. Network routes remain active.`}
          </div>
        </motion.div>
        )
      )}

      {/* ── Tab 2: Company Knowledge Graph ───────────────────────────── */}
      {activeTab === "brain" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            {/* Service & Team Governance */}
            <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] space-y-2.5">
              <div className="text-xs font-bold text-[#302B30] uppercase border-b border-[#EEE6DC] pb-1.5 tracking-wider">
                Service & Team Governance
              </div>
              <div className="space-y-1.5 text-[#645C64]">
                <div>Connected Service: <strong className="text-[#302B30]">{companyBrain?.service_name || "Corporate Device Gateway (svc-endpoint-gw)"}</strong></div>
                <div>Service Criticality: <strong className="text-[#C24128]">Tier-1 Mission Critical</strong></div>
                <div>Code Repository: <strong className="text-[#82465D]">rootmesh/device-mgmt</strong></div>
                <div>Owning Team: <strong className="text-[#302B30]">{companyBrain?.team_name || "Owner not resolved"}</strong></div>
                <div>Incident Channel: <strong className="text-[#82465D]">#secops-incidents</strong></div>
                <div>Escalation Schedule: <strong className="text-[#302B30]">PD-SECOPS-P1 (24x7)</strong></div>
              </div>
            </div>

            {/* Personnel & Runbook */}
            <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] space-y-2.5">
              <div className="text-xs font-bold text-[#302B30] uppercase border-b border-[#EEE6DC] pb-1.5 tracking-wider">
                On-Call Lead & Incident Playbook
              </div>
              <div className="space-y-1.5 text-[#645C64]">
                <div>Primary On-Call: <strong className="text-[#302B30]">{companyBrain?.person_name || companyBrain?.oncall_name || "Unassigned"}</strong></div>
                <div>On-Call Role: <strong className="text-[#302B30]">{companyBrain?.oncall_role || "Lead Incident Responder"}</strong></div>
                <div>SOP Playbook: <strong className="text-[#A06316]">{companyBrain?.runbook_title || "Workstation Lateral Movement Containment SOP (rb-iso-001)"}</strong></div>
                <div>Response SLA: <strong className="text-[#C24128]">{companyBrain?.runbook_sla_minutes ? `${companyBrain.runbook_sla_minutes} Minutes Maximum` : "15 Minutes Maximum"}</strong></div>
                <div>Protocol Steps: <strong className="text-[#302B30]">5 Verified Containment Procedures</strong></div>
                <div>Change Commit: <strong className="text-[#82465D]">{companyBrain?.commit_sha || "c89e1a4 (deploy Zero-Trust SMB endpoint policy)"}</strong></div>
              </div>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-[#FAF7F2] border border-[#DFD6C9] text-[11px] font-mono text-[#928992] text-center italic">
            * All Company Brain records (personnel, runbook links, commits) are synthetic demonstration graph data in FalkorDB for evaluation.
          </div>
        </motion.div>
      )}

      {/* ── Tab 3: Threat Memory & Audit Trail ────────────────────────── */}
      {activeTab === "memory" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          {/* Persisted Findings */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-[#302B30] uppercase font-mono tracking-wider">
              Episodic Investigation Findings (FalkorDB Memory Nodes)
            </span>
            <div className="space-y-2">
              {findings.map((f, i) => (
                <div
                  key={f.id || i}
                  className="p-3 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-xs font-mono flex items-start gap-3"
                >
                  <span className="px-2 py-0.5 rounded bg-[#FBF0ED] text-[#C24128] font-bold text-[10px] border border-[#F3C4B8]">
                    {f.severity || "HIGH"}
                  </span>
                  <div className="flex-1 text-[#302B30]">{f.text}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Procedural Memory & Audit Records */}
          <div className="space-y-2 pt-2 border-t border-[#EEE6DC]">
            <span className="text-xs font-bold text-[#302B30] uppercase font-mono tracking-wider">
              Procedural Response Memory & Durable Audit Trail
            </span>
            {auditLog.length === 0 ? (
              <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-xs font-mono text-[#645C64] text-center space-y-1">
                <span className="text-[#82465D] font-bold">No containment actions executed for {incidentId}.</span>
                <p className="text-[11px] text-[#928992]">
                  Procedural memory and FalkorDB audit records will be generated upon explicit human authorization and execution.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {auditLog.map((a, i) => (
                  <div
                    key={a.audit_id || i}
                    className="p-3.5 rounded-xl bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono space-y-1.5"
                  >
                    <div className="flex justify-between items-center">
                      <strong className="text-[#302B30]">ACTION: CONTAIN_HOST_SIMULATION</strong>
                      <span className="px-2 py-0.5 rounded bg-[#E8F2EC] text-[#26694E] font-bold text-[10px] border border-[#C5DFD0]">
                        {a.verification || "VERIFIED"}
                      </span>
                    </div>
                    <div className="text-[#645C64] text-[11px] flex flex-wrap gap-4 pt-0.5">
                      <span>Audit ID: <strong className="text-[#82465D]">{a.audit_id}</strong></span>
                      <span>Action: <strong className="text-[#302B30]">{a.action_id}</strong></span>
                      <span>Executed By: <strong className="text-[#302B30]">{a.executed_by}</strong></span>
                      <span>Paths Severed: <strong className="text-[#C24128]">{a.paths_severed}</strong></span>
                      <span>Egress Reduced: <strong className="text-[#26694E]">{a.egress_reduced_mbps} Mbps</strong></span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </motion.div>
      )}
    </div>
  );
};
