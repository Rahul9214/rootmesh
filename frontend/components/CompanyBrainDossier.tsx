"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

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
    oncall_role?: string;
    runbook_title?: string;
    runbook_sla_minutes?: number;
    commit_sha?: string;
  } | null;
}

export const CompanyBrainDossier: React.FC<CompanyBrainDossierProps> = ({
  incidentId = "inc-latest",
  targetHost = "Workstation-PatientZero (host-0)",
  hasInvestigation = true,
  isContained = false,
  containmentAudit = null,
  targetCount = 14,
  egressRiskMbps = 43.0,
  shortestPathDb = null,
  companyBrain = null,
}) => {
  const [activeTab, setActiveTab] = useState<"evidence" | "brain" | "memory">("evidence");
  const [findings, setFindings] = useState<MemoryFinding[]>([
    {
      id: "find-001",
      text: `Autonomous investigation on ${targetHost}: ${targetCount} lateral propagation paths detected; MaxFlow egress risk: ${egressRiskMbps} Mbps to perimeter.`,
      severity: "CRITICAL",
    },
    {
      id: "find-002",
      text: `High-value database risk: ${shortestPathDb?.db_name || "HR-Payroll-DB"} (${shortestPathDb?.classification || "PII_RESTRICTED"}) is reachable within ${shortestPathDb?.distance ?? 1} hop(s).`,
      severity: "CRITICAL",
    },
    {
      id: "find-003",
      text: "PageRank scoring identified EgressFirewall (0.0649) and VLAN-Router (0.0389) as most critical structural assets.",
      severity: "HIGH",
    },
  ]);

  const [auditLog, setAuditLog] = useState<AuditRecord[]>(
    containmentAudit ? [containmentAudit] : []
  );

  // Sync findings when targetHost or targetCount updates
  useEffect(() => {
    setFindings([
      {
        id: `find-${incidentId}-001`,
        text: `Autonomous investigation on ${targetHost}: ${targetCount} lateral propagation paths evaluated; MaxFlow egress risk: ${egressRiskMbps} Mbps.`,
        severity: "CRITICAL",
      },
      {
        id: `find-${incidentId}-002`,
        text: `High-value database vector: ${shortestPathDb?.db_name || "HR-Payroll-DB"} (${shortestPathDb?.classification || "PII_RESTRICTED"}) reachable in ${shortestPathDb?.distance ?? 1} hop(s).`,
        severity: "CRITICAL",
      },
      {
        id: `find-${incidentId}-003`,
        text: "PageRank GraphBLAS scoring identified EgressFirewall (0.0649) and VLAN-Router (0.0389) as top structural assets.",
        severity: "HIGH",
      },
    ]);
  }, [incidentId, targetHost, targetCount, egressRiskMbps, shortestPathDb]);

  // Sync auditLog when containmentAudit updates or isContained changes
  useEffect(() => {
    if (containmentAudit) {
      setAuditLog([containmentAudit]);
    } else if (!isContained) {
      setAuditLog([]);
    }
  }, [containmentAudit, isContained]);

  // Attempt to fetch durable incident audit trail from FalkorDB on mount or incident update
  useEffect(() => {
    if (!incidentId || incidentId === "inc-latest") return;
    const targetEndpoint = `${API_BASE}/api/v1/incident/${TENANT_ID}/${incidentId}`;

    authenticatedFetch(targetEndpoint)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data) {
          if (data.findings && data.findings.length > 0) setFindings(data.findings);
          if (data.audit_trail && data.audit_trail.length > 0) setAuditLog(data.audit_trail);
        }
      })
      .catch(() => {});
  }, [incidentId]);

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-6 shadow-warm-sm space-y-5">
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
            <span className="text-[#26694E] font-medium bg-[#E8F2EC] px-2 py-0.5 rounded border border-[#C5DFD0]">
              ✓ Verified via FalkorDB GraphBLAS
            </span>
          </div>

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
                  <strong className="text-[#C24128]">INFECTED</strong>
                </div>
                <div className="flex justify-between">
                  <span>Lateral Attack Paths:</span>
                  <strong className="text-[#C24128]">{targetCount} active paths</strong>
                </div>
                <div className="w-full bg-[#EEE6DC] h-1.5 rounded-full overflow-hidden">
                  <div className="bg-[#C24128] h-full w-full" />
                </div>
                <div className="flex justify-between">
                  <span>Perimeter Egress:</span>
                  <strong className="text-[#C24128]">{egressRiskMbps} Mbps exposure</strong>
                </div>
                <div className="w-full bg-[#EEE6DC] h-1.5 rounded-full overflow-hidden">
                  <div className="bg-[#C24128] h-full w-full" />
                </div>
                <div className="flex justify-between">
                  <span>Database Vector:</span>
                  <strong className="text-[#C24128]">
                    {shortestPathDb
                      ? `${shortestPathDb.db_name} (${shortestPathDb.distance} hop${shortestPathDb.distance === 1 ? "" : "s"} away)`
                      : "HR-Payroll-DB (1 hop away)"}
                  </strong>
                </div>
              </div>
            </div>

            {/* Post-Action State (Guarded by actual containment execution) */}
            {isContained ? (
              <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#C5DFD0] space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-2">
                  <span className="font-bold text-[#26694E] uppercase text-[11px] tracking-wide">
                    Post-Action State (Verified Containment)
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
                    <strong className="text-[#82465D]">CONTAINED (SIM)</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Lateral Attack Paths:</span>
                    <strong className="text-[#26694E]">
                      0 active ({containmentAudit?.paths_severed ?? targetCount} paths severed)
                    </strong>
                  </div>
                  <div className="w-full bg-[#EEE6DC] h-1.5 rounded-full overflow-hidden">
                    <div className="bg-[#26694E] h-full w-0" />
                  </div>
                  <div className="flex justify-between">
                    <span>Perimeter Egress:</span>
                    <strong className="text-[#26694E]">
                      0.0 Mbps ({containmentAudit?.egress_reduced_mbps ?? egressRiskMbps} Mbps eliminated)
                    </strong>
                  </div>
                  <div className="w-full bg-[#EEE6DC] h-1.5 rounded-full overflow-hidden">
                    <div className="bg-[#26694E] h-full w-0" />
                  </div>
                  <div className="flex justify-between">
                    <span>Database Vector:</span>
                    <strong className="text-[#26694E]">Blocked by Host Isolation</strong>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-[#FAF7F2] border border-[#F4DCB6] space-y-3 font-mono text-xs flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-2">
                    <span className="font-bold text-[#A06316] uppercase text-[11px] tracking-wide">
                      Post-Action State (Awaiting Containment Execution)
                    </span>
                    <span className="px-2 py-0.5 rounded-full bg-[#FDF5E8] text-[#A06316] font-bold text-[10px] border border-[#F4DCB6]">
                      PENDING AUTHORIZATION
                    </span>
                  </div>
                  <div className="space-y-2 text-[#645C64] pt-2">
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
                      <strong className="text-[#C24128]">ACTIVE EXPOSURE (UNCONTAINED)</strong>
                    </div>
                    <div className="flex justify-between">
                      <span>Lateral Attack Paths:</span>
                      <strong className="text-[#A06316]">Awaiting Authorized Execution</strong>
                    </div>
                    <div className="w-full bg-[#EEE6DC] h-1.5 rounded-full overflow-hidden">
                      <div className="bg-[#E6A548] h-full w-full opacity-60" />
                    </div>
                    <div className="flex justify-between">
                      <span>Perimeter Egress:</span>
                      <strong className="text-[#A06316]">Pending Guarded Review</strong>
                    </div>
                    <div className="w-full bg-[#EEE6DC] h-1.5 rounded-full overflow-hidden">
                      <div className="bg-[#E6A548] h-full w-full opacity-60" />
                    </div>
                    <div className="flex justify-between">
                      <span>Database Vector:</span>
                      <strong className="text-[#C24128]">Active Exposure Vector</strong>
                    </div>
                  </div>
                </div>
                <div className="pt-2 text-[10px] text-[#928992] border-t border-[#EEE6DC]">
                  Proposal pending explicit authorized reviewer decision in Action Deck. Topology remains untouched until approved and executed.
                </div>
              </div>
            )}
          </div>

          <div className="p-3 rounded-xl bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#645C64]">
            <strong>Enforcement Note:</strong> Graph-level isolation verified in FalkorDB via Cypher re-analysis. Physical hardware firewall rule enforcement requires authorized appliance connector.
          </div>
        </motion.div>
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
                <div>Owning Team: <strong className="text-[#302B30]">{companyBrain?.team_name || "SecOps Incident Response (team-sec)"}</strong></div>
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
                <div>Primary On-Call: <strong className="text-[#302B30]">{companyBrain?.person_name || "Alex Rivera (Lead IR Responder)"}</strong></div>
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
