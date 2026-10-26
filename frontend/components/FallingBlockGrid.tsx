"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";
import { threatStream, type ThreatStreamEvent } from "@/lib/threatStream";

interface ThreatNode {
  id: string;
  name: string;
  ip: string;
  status: "SAFE" | "INFECTED" | "CONTAINED";
  hops: number;
}

const INITIAL_NODES: ThreatNode[] = [
  { id: "host-0", name: "Workstation-PatientZero", ip: "10.0.1.15",  status: "INFECTED", hops: 0 },
  { id: "host-1", name: "AppServer-Internal",      ip: "10.0.2.10",  status: "SAFE",     hops: 1 },
  { id: "host-2", name: "FileBackupServer",         ip: "10.0.2.22",  status: "SAFE",     hops: 1 },
  { id: "host-3", name: "VLAN-Router",              ip: "10.0.3.1",   status: "SAFE",     hops: 2 },
  { id: "host-4", name: "JumpServer-SysAdmin",      ip: "10.0.4.5",   status: "SAFE",     hops: 3 },
  { id: "host-5", name: "ReverseProxy",             ip: "10.0.5.1",   status: "SAFE",     hops: 3 },
  { id: "host-6", name: "PublicWebServer",          ip: "10.0.5.80",  status: "SAFE",     hops: 4 },
  { id: "host-7", name: "EgressFirewall",           ip: "10.0.99.254",status: "SAFE",     hops: 4 },
];

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

interface GridProposalState {
  hostId: string;
  hostName: string;
  actionId: string;
  incidentId: string;
  lateralTargets: number;
  maxEgressMbps: number;
}

export interface FallingBlockGridProps {
  tenantId?: string;
  activeTargetHostId?: string;
  activeIncidentId?: string;
  isContained?: boolean;
  onProposalCreated?: (proposal: Record<string, unknown>) => void;
  onProposalReviewed?: (decision: "APPROVE" | "REJECT", proposal: Record<string, unknown>) => void;
  onExecutionStarted?: (actionId: string) => void;
  onExecutionFailed?: (error: string) => void;
  onContainmentExecuted?: (auditData: Record<string, unknown>) => void;
}

export const FallingBlockGrid: React.FC<FallingBlockGridProps> = ({
  tenantId,
  activeTargetHostId,
  activeIncidentId,
  isContained = false,
  onProposalCreated,
  onProposalReviewed,
  onExecutionStarted,
  onExecutionFailed,
  onContainmentExecuted,
}) => {
  const [nodes, setNodes] = useState<ThreatNode[]>(INITIAL_NODES);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);
  const [wsStatus, setWsStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const [proposingId, setProposingId] = useState<string | null>(null);
  const [pendingProposal, setPendingProposal] = useState<GridProposalState | null>(null);
  const [isReviewing, setIsReviewing] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  // Fetch live topology directly from FalkorDB on mount or tenant change
  useEffect(() => {
    if (!tenantId) {
      setNodes(INITIAL_NODES);
      return;
    }
    authenticatedFetch(`${API_BASE}/api/v1/threat/topology/${tenantId}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data: ThreatNode[] | null) => {
        if (data && data.length > 0) {
          setNodes(data);
        }
      })
      .catch(() => {});
  }, [tenantId]);

  // Propose containment (Responder role - requires verified persisted incident)
  const handleProposeContainment = useCallback(
    async (node: ThreatNode) => {
      if (!tenantId) {
        setFeedback("Authorization required: No active tenant context.");
        return;
      }

      // Preserve Human-in-the-Loop & verified incident constraint
      const effectiveIncidentId =
        node.id === activeTargetHostId &&
        activeIncidentId &&
        activeIncidentId.startsWith("inc-") &&
        activeIncidentId !== "inc-latest"
          ? activeIncidentId
          : null;

      if (!effectiveIncidentId) {
        setFeedback(
          `Cannot propose containment for ${node.name} (${node.id}): A verified, persisted incident is required. Please run an investigation first.`
        );
        return;
      }

      setProposingId(node.id);
      setFeedback(`Generating containment proposal for ${node.name}…`);

      try {
        const propRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/propose`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            incident_id: effectiveIncidentId,
            target_host_id: node.id,
            tenant_id: tenantId,
            justification: `Interactive Attack Grid Containment: ${node.name} (${node.id})`,
          }),
        });

        if (propRes.ok) {
          const propData = await propRes.json();
          setPendingProposal({
            hostId: node.id,
            hostName: node.name,
            actionId: propData.action_id,
            incidentId: propData.incident_id,
            lateralTargets:
              typeof propData.risk_assessment?.lateral_targets === "number"
                ? propData.risk_assessment.lateral_targets
                : 0,
            maxEgressMbps:
              typeof propData.risk_assessment?.max_egress_mbps === "number"
                ? propData.risk_assessment.max_egress_mbps
                : 0,
          });
          onProposalCreated?.(propData);
          setFeedback(`Proposal ${propData.action_id} created. Awaiting authorized reviewer decision.`);
        } else {
          const errJson = await propRes.json().catch(() => ({}));
          setFeedback(`Proposal error: ${errJson.detail || `HTTP ${propRes.status}`}`);
        }
      } catch {
        setFeedback("Failed to reach RootMesh backend service.");
      } finally {
        setProposingId(null);
      }
    },
    [tenantId, activeTargetHostId, activeIncidentId, onProposalCreated]
  );

  // Explicit Human Review Decision
  const handleReviewDecision = async (decision: "APPROVE" | "REJECT") => {
    if (!pendingProposal) return;
    setIsReviewing(true);

    try {
      const revRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_id: pendingProposal.actionId,
          decision,
          comment:
            decision === "APPROVE"
              ? "Authorized review approval from Threat Propagation Grid"
              : "Reviewer rejected containment proposal (fail-closed)",
        }),
      });

      if (!revRes.ok) {
        const errJson = await revRes.json().catch(() => ({}));
        setFeedback(`Review rejected: ${errJson.detail || `HTTP ${revRes.status}`}`);
        setIsReviewing(false);
        return;
      }

      const revData = await revRes.json().catch(() => ({}));
      onProposalReviewed?.(decision, revData);

      if (decision === "APPROVE") {
        onExecutionStarted?.(pendingProposal.actionId);
        const execRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/execute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action_id: pendingProposal.actionId,
            idempotency_key: `grid-${pendingProposal.hostId}-${Date.now()}`,
          }),
        });

        if (execRes.ok) {
          const auditData = await execRes.json();
          const severed =
            auditData.before_after?.paths_severed !== undefined
              ? auditData.before_after.paths_severed
              : pendingProposal.lateralTargets;
          const egress =
            auditData.before_after?.egress_reduction_mbps !== undefined
              ? auditData.before_after.egress_reduction_mbps
              : pendingProposal.maxEgressMbps;

          setNodes((prev) =>
            prev.map((n) => (n.id === pendingProposal.hostId ? { ...n, status: "CONTAINED" } : n))
          );
          setFeedback(
            `✓ APPROVED & CONTAINED (${auditData.containment_type || "GRAPH_TOPOLOGY_SIMULATION"}) · Severed: ${severed} paths · Reduced Egress: ${egress} Mbps`
          );
          onContainmentExecuted?.(auditData);
        } else {
          const errJson = await execRes.json().catch(() => ({}));
          const errDetail = errJson.detail || `HTTP ${execRes.status}`;
          setFeedback(`Execution failed: ${errDetail}`);
          onExecutionFailed?.(errDetail);
        }
      } else {
        setFeedback(
          `✕ REJECTED: Containment proposal ${pendingProposal.actionId} for ${pendingProposal.hostName} was rejected. Graph topology unchanged.`
        );
      }
    } catch {
      setFeedback("Error communicating with incident response service.");
      onExecutionFailed?.("Error communicating with incident response service.");
    } finally {
      setIsReviewing(false);
      setPendingProposal(null);
    }
  };

  // Synchronize with shared authoritative threat stream
  useEffect(() => {
    if (!tenantId) {
      setWsStatus("offline");
      return;
    }

    const unsubStatus = threatStream.onStatusChange(setWsStatus);

    const unsubEvents = threatStream.subscribe((evt: ThreatStreamEvent) => {
      if (evt.event === "INCIDENT_CONTAINMENT_EXECUTED" && evt.target_host_id) {
        setNodes((prev) =>
          prev.map((n) => (n.id === evt.target_host_id ? { ...n, status: "CONTAINED" } : n))
        );
      } else if (evt.event === "ATTACK_PROPAGATION_COMPUTED") {
        setNodes((prev) =>
          prev.map((n) =>
            n.id !== evt.patient_zero && n.status === "SAFE"
              ? { ...n, status: "INFECTED" }
              : n
          )
        );
      }
    });

    const unsubReconnect = threatStream.onReconnect(() => {
      authenticatedFetch(`${API_BASE}/api/v1/threat/topology/${tenantId}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((data: ThreatNode[] | null) => {
          if (data && data.length > 0) {
            setNodes(data);
          }
        })
        .catch(() => {});
    });

    return () => {
      unsubStatus();
      unsubEvents();
      unsubReconnect();
    };
  }, [tenantId]);

  const infected = nodes.filter((n) => n.status === "INFECTED").length;
  const contained = nodes.filter((n) => n.status === "CONTAINED").length;
  const safe = nodes.filter((n) => n.status === "SAFE").length;

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-4 sm:p-6 shadow-warm-sm space-y-4">
      {/* ── Section Header ────────────────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3 border-b border-[#EEE6DC] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#D26A50]" />
            <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
              Live Threat Propagation Matrix
            </h3>
          </div>
          <p className="text-xs text-[#645C64] mt-0.5">
            Real-time FalkorDB graph-derived asset status & lateral blast radius
          </p>
        </div>

        <div className="flex items-center gap-2.5 text-xs font-mono">
          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border ${
              wsStatus === "live"
                ? "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]"
                : wsStatus === "connecting"
                ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]"
                : "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]"
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                wsStatus === "live" ? "bg-[#26694E] animate-pulse" : "bg-[#C24128]"
              }`}
            />
            <span>{wsStatus === "live" ? "RESP Live" : "Syncing"}</span>
          </span>

          <span className="text-[#C24128] font-bold">⚠ {infected} Infected</span>
          <span className="text-[#82465D] font-bold">🔒 {contained} Contained</span>
          <span className="text-[#26694E] font-medium hidden sm:inline">✓ {safe} Safe</span>
        </div>
      </div>

      {/* ── Guarded Review Authorization Banner ──────────────────────── */}
      {pendingProposal && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 rounded-xl bg-[#FDF5E8] border border-[#E6A548] shadow-warm-sm space-y-2.5"
        >
          <div className="flex flex-wrap justify-between items-center gap-2">
            <div className="flex items-center gap-2">
              <span className="text-sm">🛡️</span>
              <span className="text-xs font-bold font-mono text-[#302B30] uppercase">
                Containment Authorization Required
              </span>
            </div>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#FAF7F2] text-[#82465D] border border-[#DFD6C9]">
              GRAPH_TOPOLOGY_SIMULATION
            </span>
          </div>

          <div className="text-xs font-mono text-[#645C64] flex flex-wrap gap-x-4 gap-y-1">
            <span>
              Target: <strong className="text-[#302B30]">{pendingProposal.hostName} ({pendingProposal.hostId})</strong>
            </span>
            <span>
              Action: <strong className="text-[#82465D]">{pendingProposal.actionId}</strong>
            </span>
            <span>
              Paths Severed: <strong className="text-[#C24128]">{pendingProposal.lateralTargets}</strong>
            </span>
            <span>
              Egress Cut: <strong className="text-[#A06316]">{pendingProposal.maxEgressMbps} Mbps</strong>
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              onClick={() => handleReviewDecision("APPROVE")}
              disabled={isReviewing}
              className="px-3.5 py-1.5 rounded-lg bg-[#26694E] hover:bg-[#1E543E] text-white font-semibold text-xs transition-all shadow-warm-xs disabled:opacity-50"
            >
              {isReviewing ? "Executing in FalkorDB…" : "✓ Approve & Execute (Admin Role)"}
            </button>
            <button
              onClick={() => handleReviewDecision("REJECT")}
              disabled={isReviewing}
              className="px-3.5 py-1.5 rounded-lg bg-[#C24128] hover:bg-[#A3351F] text-white font-semibold text-xs transition-all shadow-warm-xs disabled:opacity-50"
            >
              ✕ Reject Proposal
            </button>
            <button
              onClick={() => setPendingProposal(null)}
              className="px-2.5 py-1.5 rounded-lg bg-[#FAF7F2] hover:bg-[#EEE6DC] text-[#645C64] text-xs font-mono border border-[#DFD6C9] ml-auto"
            >
              Dismiss
            </button>
          </div>
        </motion.div>
      )}

      {/* Action Feedback */}
      {feedback && (
        <div className="text-[11px] font-mono text-[#302B30] bg-[#F5EFE6] px-3.5 py-2 rounded-xl border border-[#DFD6C9]">
          {feedback}
        </div>
      )}

      {/* ── Animated Matrix Grid ──────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        <AnimatePresence>
          {nodes.map((node, index) => {
            const isSelected = selectedNode?.id === node.id;
            const isTargetHost = node.id === activeTargetHostId;
            const isHistoricalSim = node.status === "CONTAINED" && isTargetHost && !isContained;
            const isVerifiedContained = isTargetHost && isContained;

            const displayStatus = isHistoricalSim
              ? "CONTAINED (PRIOR SIM)"
              : isVerifiedContained
              ? "CONTAINED (VERIFIED)"
              : node.status === "CONTAINED"
              ? "CONTAINED (SIM)"
              : node.status;

            const canPropose = (node.status === "INFECTED" || isHistoricalSim) && !isContained;

            const cardStyle =
              node.status === "INFECTED"
                ? "bg-[#FBF0ED] border-[#F3C4B8] hover:border-[#D26A50]"
                : isHistoricalSim
                ? "bg-[#FDF5E8] border-[#F4DCB6] hover:border-[#E6A548]"
                : node.status === "CONTAINED"
                ? "bg-[#F6EDF1] border-[#E5CDD8] hover:border-[#82465D]"
                : "bg-[#FFFFFF] border-[#DFD6C9] hover:border-[#C8BEB0]";

            const badgeStyle =
              node.status === "INFECTED"
                ? "bg-[#F3C4B8] text-[#C24128]"
                : isHistoricalSim
                ? "bg-[#FDF5E8] text-[#A06316] border border-[#F4DCB6]"
                : node.status === "CONTAINED"
                ? "bg-[#E5CDD8] text-[#82465D]"
                : "bg-[#E8F2EC] text-[#26694E]";

            return (
              <motion.div
                key={node.id}
                initial={{ opacity: 0, y: -16, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.92 }}
                transition={{ duration: 0.35, delay: index * 0.03, type: "spring", stiffness: 180 }}
                onClick={() => setSelectedNode(node)}
                tabIndex={0}
                role="button"
                aria-label={`Node ${node.name}, status ${displayStatus}`}
                onKeyDown={(e) => e.key === "Enter" && setSelectedNode(node)}
                className={`relative p-3.5 rounded-xl border flex flex-col justify-between h-32 cursor-pointer transition-all focus:outline-none focus:ring-2 focus:ring-[#D26A50] shadow-warm-xs interactive-lift ${cardStyle} ${
                  isSelected ? "ring-2 ring-[#D26A50] shadow-warm-md" : ""
                }`}
              >
                <div className="flex justify-between items-start">
                  <span className="text-[10px] font-mono text-[#645C64] font-medium">
                    {node.id}
                  </span>
                  <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wide ${badgeStyle}`}>
                    {displayStatus}
                  </span>
                </div>

                <div>
                  <p className="text-xs font-bold text-[#302B30] leading-tight truncate">
                    {node.name}
                  </p>
                  <p className="text-[10px] text-[#645C64] font-mono mt-0.5">
                    {node.ip}
                  </p>
                </div>

                <div className="flex justify-between items-center pt-1 border-t border-black/5">
                  <span className="text-[10px] text-[#645C64] font-mono">
                    Hop {node.hops}
                  </span>
                  {canPropose && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleProposeContainment(node);
                      }}
                      disabled={proposingId === node.id || !!pendingProposal}
                      className="text-[10px] px-2 py-0.5 rounded-md bg-[#D26A50] hover:bg-[#BE5B42] text-white font-medium shadow-warm-xs transition-colors disabled:opacity-50"
                    >
                      {proposingId === node.id ? "Proposing…" : "Contain (Sim)"}
                    </button>
                  )}
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>

      {/* ── Slide-Out Node Inspector Drawer ───────────────────────────── */}
      {selectedNode && (() => {
        const isTargetHost = selectedNode.id === activeTargetHostId;
        const isHistoricalSim = selectedNode.status === "CONTAINED" && isTargetHost && !isContained;
        const isVerifiedContained = isTargetHost && isContained;
        const drawerDisplayStatus = isHistoricalSim
          ? "CONTAINED (PRIOR SIM - Awaiting Incident Review)"
          : isVerifiedContained
          ? "CONTAINED (VERIFIED TOPOLOGY)"
          : selectedNode.status === "CONTAINED"
          ? "CONTAINED (SIM)"
          : selectedNode.status;
        const canProposeDrawer = (selectedNode.status === "INFECTED" || isHistoricalSim) && !isContained;

        return (
          <div className="p-4 rounded-xl bg-[#F5EFE6] border border-[#DFD6C9] flex flex-wrap items-center justify-between gap-3 text-xs font-mono shadow-warm-xs">
            <div className="flex items-center gap-3">
              <span className="text-lg">🔎</span>
              <div>
                <span className="font-bold text-[#302B30] text-sm">{selectedNode.name}</span>{" "}
                <span className="text-[#645C64]">({selectedNode.id} · {selectedNode.ip})</span>
                <div className="text-[11px] text-[#645C64] mt-0.5">
                  Current Status: <strong className={selectedNode.status === "INFECTED" ? "text-[#C24128]" : isHistoricalSim ? "text-[#A06316]" : isVerifiedContained ? "text-[#26694E]" : "text-[#82465D]"}>{drawerDisplayStatus}</strong> · Propagation Distance: <strong>{selectedNode.hops === 0 ? "Patient Zero (Infected Origin Host)" : `${selectedNode.hops} hop${selectedNode.hops === 1 ? "" : "s"} from patient zero`}</strong>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {canProposeDrawer && (
                <button
                  onClick={() => handleProposeContainment(selectedNode)}
                  disabled={proposingId === selectedNode.id || !!pendingProposal}
                  className="px-3.5 py-1.5 rounded-lg bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-xs shadow-warm-xs transition-colors disabled:opacity-50"
                >
                  Propose Containment (Sim)
                </button>
              )}
              <button
                onClick={() => setSelectedNode(null)}
                className="px-3 py-1.5 rounded-lg bg-[#FFFFFF] text-[#645C64] border border-[#DFD6C9] hover:bg-[#EEE6DC] transition-colors font-medium"
              >
                Close
              </button>
            </div>
          </div>
        );
      })()}
    </div>
  );
};
