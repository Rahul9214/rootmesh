"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

export interface LifecycleStage {
  id: string;
  name: string;
  subtitle: string;
  actor: string;
  status: "completed" | "active" | "pending";
  timestamp: string;
  details: string;
  evidenceKey?: string;
  evidencePayload?: Record<string, unknown>;
}

interface IncidentJourneyTimelineProps {
  currentStageId?: string;
  incidentId?: string;
  targetHost?: string;
  hasInvestigation?: boolean;
  hasProposal?: boolean;
  hasReview?: boolean;
  hasExecution?: boolean;
  onSelectStage?: (stageId: string) => void;
}

export const IncidentJourneyTimeline: React.FC<IncidentJourneyTimelineProps> = ({
  incidentId = "inc-latest",
  targetHost = "Workstation-PatientZero (host-0)",
  hasInvestigation = true,
  hasProposal = false,
  hasReview = false,
  hasExecution = false,
  onSelectStage,
}) => {
  const [selectedStage, setSelectedStage] = useState<LifecycleStage | null>(null);

  const stages: LifecycleStage[] = [
    {
      id: "detection",
      name: "Detection",
      subtitle: "Telemetry Ingestion",
      actor: "Sensor / EDR",
      status: "completed",
      timestamp: "14:20:00 UTC",
      details: `Suspicious outbound lateral beaconing identified from ${targetHost}. Ingested into FalkorDB threat graph.`,
      evidenceKey: "TELEMETRY_ANOMALY_001",
      evidencePayload: {
        source: "EndpointAgent",
        event_type: "LATERAL_SMB_BURST",
        target: targetHost,
        severity: "HIGH",
      },
    },
    {
      id: "investigation",
      name: "Investigation",
      subtitle: "Autonomous Graph Traversal",
      actor: "TriageAgent",
      status: hasInvestigation ? "completed" : "active",
      timestamp: hasInvestigation ? "14:20:02 UTC" : "In Progress",
      details: "Multi-hop Cypher traversal evaluated 14 lateral exposure paths and Monte Carlo blast radius in sub-millisecond graph queries.",
      evidenceKey: "GRAPH_TRAVERSAL_PATHS",
      evidencePayload: {
        traversal_hops: 4,
        paths_evaluated: 14,
        reachable_hosts: 7,
        algorithm: "FalkorDB GraphBLAS",
      },
    },
    {
      id: "evidence",
      name: "Evidence",
      subtitle: "Bottleneck & DB Risk",
      actor: "MitigationAgent",
      status: hasInvestigation ? "completed" : "pending",
      timestamp: hasInvestigation ? "14:20:03 UTC" : "Pending",
      details: "MaxFlow perimeter egress evaluated at 43.0 Mbps bottleneck. Shortest path to HR-Payroll-DB (PII_RESTRICTED) resolved.",
      evidenceKey: "MAXFLOW_EGRESS_METRICS",
      evidencePayload: {
        max_egress_mbps: 43.0,
        high_value_target: "HR-Payroll-DB",
        classification: "PII_RESTRICTED",
        proximity: "1 hop via FileBackupServer",
      },
    },
    {
      id: "proposal",
      name: "Proposal",
      subtitle: "Containment Formulation",
      actor: "Responder (alex.rivera)",
      status: hasProposal || hasReview || hasExecution ? "completed" : hasInvestigation ? "active" : "pending",
      timestamp: hasProposal || hasReview || hasExecution ? "14:21:10 UTC" : "Awaiting Action",
      details: "Containment plan formulated: isolate host-0 topology edges, severing 14 propagation vectors while preserving audit telemetry.",
      evidenceKey: "PROPOSAL_SPEC_001",
      evidencePayload: {
        action_type: "ISOLATE_HOST_TOPOLOGY",
        mode: "GRAPH_TOPOLOGY_SIMULATION",
        target_host: "host-0",
        proposer: "alex.rivera",
      },
    },
    {
      id: "review",
      name: "Human Review",
      subtitle: "Guarded Authorization Gate",
      actor: "SecOps Lead (elena.rostova)",
      status: hasReview || hasExecution ? "completed" : hasProposal ? "active" : "pending",
      timestamp: hasReview || hasExecution ? "14:22:05 UTC" : "Pending Approval",
      details: "Explicit human authorization required. Reviewer validates risk assessment, team ownership, and blast radius before execution.",
      evidenceKey: "AUTHZ_DECISION_GATE",
      evidencePayload: {
        decision: hasReview || hasExecution ? "APPROVED" : "PENDING",
        reviewer_role: "SecOps Reviewer",
        least_privilege_verified: true,
      },
    },
    {
      id: "execution",
      name: "Execution",
      subtitle: "Topological Containment",
      actor: "MitigationAgent",
      status: hasExecution ? "completed" : hasReview ? "active" : "pending",
      timestamp: hasExecution ? "14:22:08 UTC" : "Pending",
      details: "FalkorDB host firewall flag set to true; communication relationships shunted in simulated graph topology.",
      evidenceKey: "CONTAINMENT_EXECUTION_AUDIT",
      evidencePayload: {
        execution_id: "act-contain-host-0",
        containment_type: "GRAPH_TOPOLOGY_SIMULATION",
        firewall_state: hasExecution ? "ENABLED" : "DISABLED",
      },
    },
    {
      id: "verification",
      name: "Verification",
      subtitle: "Graph Re-Analysis",
      actor: "AuditService",
      status: hasExecution ? "completed" : "pending",
      timestamp: hasExecution ? "14:22:09 UTC" : "Pending",
      details: "Graph re-traversal verified: 0 active attack paths remain (14 severed). Egress reduced from 43.0 Mbps to 0.0 Mbps.",
      evidenceKey: "POST_CONTAINMENT_VERIFICATION",
      evidencePayload: {
        active_paths_remaining: hasExecution ? 0 : 14,
        paths_severed: hasExecution ? 14 : 0,
        egress_reduced_mbps: hasExecution ? 43.0 : 0.0,
        status: hasExecution ? "VERIFIED" : "UNVERIFIED",
      },
    },
    {
      id: "memory",
      name: "Memory",
      subtitle: "Episodic Persistence",
      actor: "MemoryAgent",
      status: hasExecution ? "completed" : "pending",
      timestamp: hasExecution ? "14:22:10 UTC" : "Pending",
      details: "Episodic finding and procedural audit record persisted into FalkorDB knowledge graph with durable cross-session provenance.",
      evidenceKey: "EPISODIC_GRAPH_RECORD",
      evidencePayload: {
        finding_id: "find-latest-001",
        audit_id: "aud-latest-001",
        incident_id: incidentId,
        durable_storage: "FalkorDB GraphBLAS",
      },
    },
  ];

  const handleStageClick = (stg: LifecycleStage) => {
    setSelectedStage(stg);
    if (onSelectStage) {
      onSelectStage(stg.id);
    }
  };

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-6 shadow-warm-sm space-y-5">
      {/* ── Section Header ────────────────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3 border-b border-[#EEE6DC] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#D26A50]" />
            <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
              Incident Response Lifecycle
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#FAF7F2] text-[#645C64] border border-[#DFD6C9]">
              {incidentId}
            </span>
          </div>
          <p className="text-xs text-[#645C64] mt-0.5">
            Real-time visual stepper tracking verified forensic phases from telemetry detection to episodic memory
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#26694E]" />
            <span>Guarded Lifecycle</span>
          </span>
        </div>
      </div>

      {/* ── Horizontal Stepper (Desktop & Tablet) ────────────────────── */}
      <div className="hidden md:block overflow-x-auto pb-2">
        <div className="flex items-center justify-between min-w-[760px] relative">
          {/* Background Connecting Line */}
          <div className="absolute top-5 left-6 right-6 h-0.5 bg-[#EEE6DC] -z-0" />

          {stages.map((stg, idx) => {
            const isCompleted = stg.status === "completed";
            const isActive = stg.status === "active";
            const isSelected = selectedStage?.id === stg.id;

            return (
              <button
                key={stg.id}
                onClick={() => handleStageClick(stg)}
                className="relative z-10 flex flex-col items-center group text-center focus:outline-none"
                style={{ width: `${100 / stages.length}%` }}
              >
                {/* Node Circle */}
                <div
                  className={`w-10 h-10 rounded-xl flex items-center justify-center font-mono font-bold text-xs transition-all duration-200 ${
                    isSelected
                      ? "ring-2 ring-[#D26A50] ring-offset-2 scale-110 shadow-warm-sm"
                      : ""
                  } ${
                    isCompleted
                      ? "bg-[#26694E] text-white shadow-warm-xs"
                      : isActive
                      ? "bg-[#D26A50] text-white shadow-terracotta-sm animate-pulse"
                      : "bg-[#F5EFE6] text-[#928992] border border-[#DFD6C9]"
                  }`}
                >
                  {isCompleted ? "✓" : idx + 1}
                </div>

                {/* Stage Name */}
                <span
                  className={`mt-2 text-xs font-bold font-mono transition-colors ${
                    isCompleted
                      ? "text-[#302B30]"
                      : isActive
                      ? "text-[#D26A50]"
                      : "text-[#928992]"
                  }`}
                >
                  {stg.name}
                </span>

                {/* Subtitle */}
                <span className="text-[10px] text-[#645C64] truncate max-w-[90px] font-mono">
                  {stg.subtitle}
                </span>

                {/* Status Indicator Pill */}
                <span
                  className={`mt-1 text-[9px] font-mono px-1.5 py-0.2 rounded-md ${
                    isCompleted
                      ? "bg-[#E8F2EC] text-[#26694E]"
                      : isActive
                      ? "bg-[#FBF0ED] text-[#D26A50] font-bold"
                      : "bg-[#FAF7F2] text-[#928992]"
                  }`}
                >
                  {stg.status.toUpperCase()}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Vertical Timeline (Mobile) ───────────────────────────────── */}
      <div className="md:hidden space-y-3">
        {stages.map((stg, idx) => {
          const isCompleted = stg.status === "completed";
          const isActive = stg.status === "active";

          return (
            <div
              key={stg.id}
              onClick={() => handleStageClick(stg)}
              className={`p-3 rounded-xl border transition-all cursor-pointer ${
                selectedStage?.id === stg.id
                  ? "border-[#D26A50] bg-[#FAF7F2]"
                  : "border-[#DFD6C9] bg-[#FFFFFF]"
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`w-6 h-6 rounded-lg flex items-center justify-center font-mono text-xs font-bold ${
                      isCompleted
                        ? "bg-[#26694E] text-white"
                        : isActive
                        ? "bg-[#D26A50] text-white"
                        : "bg-[#EEE6DC] text-[#645C64]"
                    }`}
                  >
                    {isCompleted ? "✓" : idx + 1}
                  </span>
                  <div>
                    <h4 className="text-xs font-bold text-[#302B30] font-mono">
                      {stg.name}
                    </h4>
                    <p className="text-[10px] text-[#645C64] font-mono">{stg.subtitle}</p>
                  </div>
                </div>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                    isCompleted
                      ? "bg-[#E8F2EC] text-[#26694E]"
                      : isActive
                      ? "bg-[#FBF0ED] text-[#D26A50] font-bold"
                      : "bg-[#FAF7F2] text-[#928992]"
                  }`}
                >
                  {stg.status.toUpperCase()}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Slide-out / Expandable Stage Evidence Drawer ────────────── */}
      <AnimatePresence>
        {selectedStage && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] p-4 text-xs font-mono space-y-3"
          >
            <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#D26A50]" />
                <span className="font-bold text-[#302B30] uppercase">
                  Stage Details: {selectedStage.name} ({selectedStage.subtitle})
                </span>
              </div>
              <button
                onClick={() => setSelectedStage(null)}
                className="text-[#645C64] hover:text-[#302B30] font-bold text-sm px-2"
              >
                ✕
              </button>
            </div>

            <p className="text-[#645C64] leading-relaxed">{selectedStage.details}</p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              <div className="bg-[#FFFFFF] p-2.5 rounded-lg border border-[#EEE6DC]">
                <span className="text-[10px] text-[#928992] uppercase block">Responsible Actor</span>
                <strong className="text-[#302B30] font-bold">{selectedStage.actor}</strong>
              </div>
              <div className="bg-[#FFFFFF] p-2.5 rounded-lg border border-[#EEE6DC]">
                <span className="text-[10px] text-[#928992] uppercase block">Recorded Timestamp</span>
                <strong className="text-[#302B30] font-bold">{selectedStage.timestamp}</strong>
              </div>
              <div className="bg-[#FFFFFF] p-2.5 rounded-lg border border-[#EEE6DC]">
                <span className="text-[10px] text-[#928992] uppercase block">Evidence Key</span>
                <strong className="text-[#82465D] font-bold">{selectedStage.evidenceKey || "N/A"}</strong>
              </div>
            </div>

            {selectedStage.evidencePayload && (
              <div className="mt-2">
                <span className="text-[10px] text-[#928992] uppercase block mb-1">
                  Structured Forensic Payload
                </span>
                <pre className="p-2.5 rounded-lg bg-[#302B30] text-[#FAF7F2] text-[11px] overflow-x-auto">
                  {JSON.stringify(selectedStage.evidencePayload, null, 2)}
                </pre>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
