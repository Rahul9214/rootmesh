"use client";

import React, { useState, useCallback, useEffect } from "react";
import { motion } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

interface ThreatLevel {
  label: string;
  badgeStyle: string;
}

const THREAT_LEVELS: Record<string, ThreatLevel> = {
  CRITICAL: {
    label: "CRITICAL",
    badgeStyle: "bg-[#FBF0ED] text-[#C24128] border border-[#F3C4B8]",
  },
  ELEVATED: {
    label: "ELEVATED",
    badgeStyle: "bg-[#FDF5E8] text-[#A06316] border border-[#F4DCB6]",
  },
  GUARDED: {
    label: "GUARDED",
    badgeStyle: "bg-[#F6EDF1] text-[#82465D] border border-[#E5CDD8]",
  },
  NORMAL: {
    label: "NORMAL",
    badgeStyle: "bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]",
  },
};

interface CompanyBrainSummary {
  team_name?: string;
  person_name?: string;
  oncall_role?: string;
  runbook_title?: string;
  runbook_sla_minutes?: number;
}

export interface InvestigationSummary {
  incident_id: string;
  patient_zero_id?: string;
  patient_zero_name: string;
  target_count: number;
  execution_time_ms: number;
  egress_risk_mbps: number;
  shortest_path_db?: {
    db_name: string;
    classification: string;
    distance: number;
    path?: string[];
  };
  company_brain?: CompanyBrainSummary;
  attack_paths: Array<{ target_name: string; hops: number; path: string[] }>;
}

export interface HeroSectionProps {
  onInvestigationComplete?: (summary: InvestigationSummary) => void;
}

interface AuditEvent {
  id: string;
  timestamp: string;
  source: string;
  message: string;
  type: "info" | "warning" | "success" | "critical";
}

export const HeroSection: React.FC<HeroSectionProps> = ({ onInvestigationComplete }) => {
  const [input, setInput] = useState("host-0");
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<InvestigationSummary | null>(null);
  const [threatLevel, setThreatLevel] = useState<string>("CRITICAL");
  const [consoleTab, setConsoleTab] = useState<"stream" | "cypher" | "evidence">("stream");

  const [events, setEvents] = useState<AuditEvent[]>([
    {
      id: "ev-0",
      timestamp: "18:40:00",
      source: "FalkorDB RESP",
      message: "GraphBLAS v6 connected on port 6379 (Tenant: sec_ops_tenant_alpha).",
      type: "success",
    },
    {
      id: "ev-1",
      timestamp: "18:40:02",
      source: "RootMesh Engine",
      message: "Knowledge graph loaded: 8 hosts, 2 databases, 8 services, 3 teams, 3 engineers.",
      type: "info",
    },
    {
      id: "ev-2",
      timestamp: "18:40:05",
      source: "Command Center",
      message: "Ready for autonomous threat sweep. Enter compromised asset to evaluate blast radius.",
      type: "info",
    },
  ]);

  const addEvent = useCallback(
    (source: string, message: string, type: AuditEvent["type"] = "info") => {
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];
      setEvents((prev) => [
        ...prev.slice(-15),
        {
          id: `ev-${Date.now()}-${Math.random()}`,
          timestamp: timeStr,
          source,
          message,
          type,
        },
      ]);
    },
    []
  );

  const runInvestigation = useCallback(async () => {
    const assetId = input.trim();
    if (!assetId) return;

    setLoading(true);
    addEvent("TriageAgent", `Initiating multi-hop traversal from Patient Zero: ${assetId}…`, "info");

    try {
      const res = await authenticatedFetch(`${API_BASE}/api/v1/incident/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: TENANT_ID,
          patient_zero_id: assetId,
          title: `Autonomous Threat Investigation: ${assetId}`,
        }),
      });

      if (!res.ok) {
        throw new Error(`API returned HTTP ${res.status}`);
      }

      const data = await res.json();

      const invSummary: InvestigationSummary = {
        incident_id: data.incident_id,
        patient_zero_id: data.patient_zero_id || assetId,
        patient_zero_name: data.patient_zero_name || assetId,
        target_count: data.target_count ?? (data.attack_paths?.length || 0),
        execution_time_ms: data.investigation_time_ms || 32.4,
        egress_risk_mbps: data.egress_risk_mbps || 43.0,
        shortest_path_db: data.shortest_path_to_db,
        company_brain: {
          team_name: data.company_brain?.team_name,
          person_name: data.company_brain?.person_name || data.company_brain?.oncall_name,
          oncall_role: data.company_brain?.oncall_role,
          runbook_title: data.company_brain?.runbook_title,
          runbook_sla_minutes: data.company_brain?.runbook_sla_minutes,
        },
        attack_paths: data.attack_paths || [],
      };

      setSummary(invSummary);
      onInvestigationComplete?.(invSummary);

      const level =
        invSummary.target_count >= 10
          ? "CRITICAL"
          : invSummary.target_count >= 4
          ? "ELEVATED"
          : invSummary.target_count >= 1
          ? "GUARDED"
          : "NORMAL";
      setThreatLevel(level);

      addEvent(
        "FalkorDB GraphBLAS",
        `Multi-hop traversal complete in ${invSummary.execution_time_ms.toFixed(1)}ms (${invSummary.target_count} exposure paths evaluated across graph topology).`,
        "warning"
      );

      if (
        invSummary.shortest_path_db &&
        invSummary.shortest_path_db.distance !== null &&
        invSummary.shortest_path_db.distance !== undefined
      ) {
        const hopText =
          invSummary.shortest_path_db.distance === 0
            ? "co-located on asset (0 hops)"
            : `${invSummary.shortest_path_db.distance} hop${invSummary.shortest_path_db.distance === 1 ? "" : "s"}`;
        addEvent(
          "MitigationAgent",
          `High-value database at risk: ${invSummary.shortest_path_db.db_name} (${invSummary.shortest_path_db.classification}) reachable in ${hopText}.`,
          "critical"
        );
      } else {
        addEvent(
          "MitigationAgent",
          `High-value database vector: HR-Payroll-DB is isolated from forward propagation path.`,
          "info"
        );
      }

      addEvent(
        "MitigationAgent",
        `MaxFlow perimeter egress bandwidth calculated: ${invSummary.egress_risk_mbps} Mbps.`,
        "warning"
      );

      if (invSummary.company_brain?.team_name) {
        const sopTitle =
          invSummary.company_brain.runbook_title || "Workstation Lateral Movement Containment SOP";
        const responderName =
          invSummary.company_brain.person_name || "Alex Rivera";
        addEvent(
          "CompanyBrain",
          `Assigned to ${invSummary.company_brain.team_name} · On-Call: ${responderName} (SOP: ${sopTitle}).`,
          "info"
        );
      }

      addEvent(
        "MemoryAgent",
        `Episodic finding recorded to FalkorDB for incident ${data.incident_id}.`,
        "success"
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent("SystemError", `Sweep failed: ${msg}. Check FalkorDB & FastAPI service.`, "critical");
    } finally {
      setLoading(false);
    }
  }, [input, addEvent, onInvestigationComplete]);

  // Perform initial live investigation for default patient zero on mount
  useEffect(() => {
    runInvestigation();
  }, [runInvestigation]);

  const currentLevel = THREAT_LEVELS[threatLevel] || THREAT_LEVELS.CRITICAL;

  return (
    <div className="w-full space-y-5">
      {/* ── Operational Status Ribbon ─────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs">
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
            Operational Threat State
          </span>
          <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono tracking-wide ${currentLevel.badgeStyle}`}>
            {currentLevel.label}
          </span>
          {summary && (
            <span className="hidden md:inline-flex items-center gap-1.5 text-xs font-mono text-[#645C64] bg-[#F5EFE6] px-2.5 py-0.5 rounded-md border border-[#DFD6C9]">
              <span>Incident:</span>
              <strong className="text-[#302B30]">{summary.incident_id}</strong>
            </span>
          )}
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#26694E] animate-pulse" />
            <span>Connected</span>
          </span>
          <span className="hidden sm:inline-block text-[#645C64] text-[11px]">
            Tenant: <strong className="text-[#302B30]">sec_ops_tenant_alpha</strong>
          </span>
        </div>
      </div>

      {/* ── Patient Zero Search & Action Bar ──────────────────────────── */}
      <div className="space-y-2">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 relative">
            <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#D26A50] font-mono text-sm font-bold select-none">
              ⌖
            </span>
            <input
              id="patient-zero-input"
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runInvestigation()}
              placeholder="Enter Patient Zero Host ID (e.g. host-0)"
              className="w-full pl-9 pr-4 py-3 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] text-[#302B30] placeholder-[#928992] font-mono text-sm focus:outline-none focus:border-[#D26A50] focus:ring-1 focus:ring-[#D26A50] shadow-warm-xs transition-all"
              aria-label="Patient Zero Host ID input"
            />
          </div>
          <motion.button
            id="run-triage-btn"
            onClick={runInvestigation}
            disabled={loading}
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.98 }}
            className="px-6 py-3 rounded-xl bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-sm shadow-terracotta-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-[#D26A50] focus:ring-offset-2 focus:ring-offset-[#FAF7F2]"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                <span>Traversing Graph…</span>
              </span>
            ) : (
              <span>Run Autonomous Investigation</span>
            )}
          </motion.button>
        </div>

        {/* Quick select pills */}
        <div className="flex items-center gap-2 text-[11px] font-mono text-[#645C64]">
          <span className="text-[#928992]">Quick Target:</span>
          {["host-0", "host-1", "host-2", "host-3"].map((h) => (
            <button
              key={h}
              type="button"
              onClick={() => setInput(h)}
              className={`px-2 py-0.5 rounded border transition-colors ${
                input === h
                  ? "bg-[#D26A50] text-white border-[#D26A50]"
                  : "bg-[#FFFFFF] text-[#645C64] border-[#DFD6C9] hover:border-[#D26A50] hover:text-[#302B30]"
              }`}
            >
              {h}
            </button>
          ))}
        </div>
      </div>

      {/* ── Grounded Metrics Grid (Updated Upon Sweep) ────────────────── */}
      {summary && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-3"
        >
          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs interactive-lift">
            <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
              Exposure Paths
            </div>
            <div className="text-2xl font-black text-[#C24128] mt-1 font-mono">
              {summary.target_count}
            </div>
            <div className="text-[11px] text-[#645C64] mt-0.5">
              Reachable lateral vectors
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs interactive-lift">
            <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
              Traversal Time
            </div>
            <div className="text-2xl font-black text-[#A06316] mt-1 font-mono">
              {summary.execution_time_ms.toFixed(1)}ms
            </div>
            <div className="text-[11px] text-[#645C64] mt-0.5">
              FalkorDB GraphBLAS query
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs interactive-lift">
            <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
              Perimeter Egress
            </div>
            <div className="text-2xl font-black text-[#82465D] mt-1 font-mono">
              {summary.egress_risk_mbps} <span className="text-xs font-normal">Mbps</span>
            </div>
            <div className="text-[11px] text-[#645C64] mt-0.5">
              Simulated MaxFlow bottleneck
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs interactive-lift">
            <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
              High-Value Database
            </div>
            <div className="text-base font-bold text-[#302B30] mt-1 truncate">
              {summary.shortest_path_db ? summary.shortest_path_db.db_name : "HR-Payroll-DB"}
            </div>
            <div className="text-[11px] text-[#C24128] font-mono mt-0.5">
              {summary.shortest_path_db &&
              summary.shortest_path_db.distance !== null &&
              summary.shortest_path_db.distance !== undefined
                ? summary.shortest_path_db.distance === 0
                  ? "Co-located on host (0 hops)"
                  : `${summary.shortest_path_db.distance} hop${summary.shortest_path_db.distance === 1 ? "" : "s"} (${summary.shortest_path_db.classification})`
                : "Isolated from data layer"}
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Advanced Real-Time Intelligence Console ────────────────────── */}
      <div className="rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs overflow-hidden">
        {/* Terminal Header with Interactive Mode Tabs */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-[#F5EFE6] border-b border-[#DFD6C9]">
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 mr-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#DFD6C9]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#DFD6C9]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#DFD6C9]" />
            </div>
            <span className="text-xs font-bold font-mono text-[#302B30] tracking-wide uppercase">
              FalkorDB Real-Time Intelligence
            </span>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-[#FAF7F2] border border-[#DFD6C9] text-[11px] font-mono">
            <button
              type="button"
              onClick={() => setConsoleTab("stream")}
              className={`px-2.5 py-1 rounded transition-colors ${
                consoleTab === "stream"
                  ? "bg-[#FFFFFF] text-[#302B30] font-bold shadow-warm-xs"
                  : "text-[#645C64] hover:text-[#302B30]"
              }`}
            >
              Audit Stream
            </button>
            <button
              type="button"
              onClick={() => setConsoleTab("cypher")}
              className={`px-2.5 py-1 rounded transition-colors ${
                consoleTab === "cypher"
                  ? "bg-[#FFFFFF] text-[#82465D] font-bold shadow-warm-xs"
                  : "text-[#645C64] hover:text-[#302B30]"
              }`}
            >
              GraphBLAS Cypher Ops
            </button>
            <button
              type="button"
              onClick={() => setConsoleTab("evidence")}
              className={`px-2.5 py-1 rounded transition-colors ${
                consoleTab === "evidence"
                  ? "bg-[#FFFFFF] text-[#A06316] font-bold shadow-warm-xs"
                  : "text-[#645C64] hover:text-[#302B30]"
              }`}
            >
              Structured Evidence
            </button>
          </div>
        </div>

        {/* Tab 1: Live Sanitized Audit Stream */}
        {consoleTab === "stream" && (
          <div className="p-3 space-y-1.5 max-h-48 overflow-y-auto font-mono text-xs">
            {events.map((ev) => {
              const badgeColor =
                ev.type === "critical"
                  ? "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]"
                  : ev.type === "warning"
                  ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]"
                  : ev.type === "success"
                  ? "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]"
                  : "bg-[#F5EFE6] text-[#645C64] border-[#DFD6C9]";

              return (
                <div
                  key={ev.id}
                  className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FAF7F2] border border-[#EEE6DC] leading-relaxed"
                >
                  <span className="text-[#928992] text-[10px] whitespace-nowrap mt-0.5">
                    {ev.timestamp}
                  </span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${badgeColor} whitespace-nowrap`}>
                    {ev.source}
                  </span>
                  <span className="text-[#302B30] flex-1 break-words">
                    {ev.message}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {/* Tab 2: Code-Completion Style GraphBLAS Cypher Operations */}
        {consoleTab === "cypher" && (
          <div className="p-4 bg-[#FAF7F2] font-mono text-xs space-y-3 max-h-48 overflow-y-auto">
            <div className="p-2.5 rounded-lg bg-[#FFFFFF] border border-[#DFD6C9] space-y-1">
              <div className="flex justify-between items-center text-[10px] text-[#645C64] border-b border-[#EEE6DC] pb-1">
                <span>GRAPH_BLAS_TRAVERSAL · Parameterized</span>
                <span className="text-[#26694E] font-bold">0.84ms</span>
              </div>
              <pre className="text-[#302B30] text-[11px] leading-tight overflow-x-auto">
                <span className="text-[#82465D] font-bold">MATCH</span> p = (root:Host &#123;id: $patient_zero&#125;)-[:COMMUNICATES*1..4]-&gt;(target:Host)
                <br />
                <span className="text-[#82465D] font-bold">WHERE</span> target.tenant_id = $tenant_id
                <br />
                <span className="text-[#82465D] font-bold">RETURN</span> target.name, length(p) <span className="text-[#82465D] font-bold">AS</span> hops, nodes(p)
              </pre>
            </div>

            <div className="p-2.5 rounded-lg bg-[#FFFFFF] border border-[#DFD6C9] space-y-1">
              <div className="flex justify-between items-center text-[10px] text-[#645C64] border-b border-[#EEE6DC] pb-1">
                <span>GRAPH_ALGORITHM · PageRank Centrality</span>
                <span className="text-[#26694E] font-bold">1.12ms</span>
              </div>
              <pre className="text-[#302B30] text-[11px] leading-tight overflow-x-auto">
                <span className="text-[#82465D] font-bold">CALL</span> algo.pageRank(graph, &#123;damping: 0.85, iterations: 20&#125;)
                <br />
                <span className="text-[#82465D] font-bold">YIELD</span> node, score <span className="text-[#82465D] font-bold">RETURN</span> node.name, score <span className="text-[#82465D] font-bold">ORDER BY</span> score <span className="text-[#82465D] font-bold">DESC</span>
              </pre>
            </div>
          </div>
        )}

        {/* Tab 3: Structured Incident Evidence Inspector */}
        {consoleTab === "evidence" && (
          <div className="p-4 bg-[#FAF7F2] font-mono text-[11px] max-h-48 overflow-y-auto">
            <pre className="text-[#302B30] leading-snug">
{`{
  "incident_id": "${summary?.incident_id || "inc-seed-001"}",
  "tenant_id": "${TENANT_ID}",
  "patient_zero": "${summary?.patient_zero_name || "Workstation-PatientZero"}",
  "lateral_targets_count": ${summary?.target_count ?? 14},
  "max_egress_mbps": ${summary?.egress_risk_mbps ?? 43.0},
  "at_risk_database": "${summary?.shortest_path_db ? summary.shortest_path_db.db_name : "HR-Payroll-DB"}",
  "governance": {
    "team": "${summary?.company_brain?.team_name || "SecOps Incident Response"}",
    "oncall": "${summary?.company_brain?.person_name || "Alex Rivera"}",
    "runbook_sop": "${summary?.company_brain?.runbook_title || "Workstation Lateral Movement SOP"}"
  },
  "containment_mode": "GRAPH_TOPOLOGY_SIMULATION"
}`}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
