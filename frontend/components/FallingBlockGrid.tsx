"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authenticatedFetch, getAuthenticatedWebSocketUrl } from "@/lib/auth";

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
const TENANT_ID = "sec_ops_tenant_alpha";

const statusStyles: Record<ThreatNode["status"], string> = {
  INFECTED:  "bg-rose-950/50  border-rose-500/80  shadow-[0_0_18px_rgba(244,63,94,0.4)]",
  CONTAINED: "bg-amber-950/40 border-amber-500/70 shadow-[0_0_12px_rgba(255,184,0,0.3)]",
  SAFE:      "bg-indigo-950/30 border-indigo-800/40 hover:border-violet-500/50",
};

const badgeStyles: Record<ThreatNode["status"], string> = {
  INFECTED:  "bg-rose-500/20  text-rose-300  border border-rose-500/40",
  CONTAINED: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
  SAFE:      "bg-emerald-500/20 text-emerald-300",
};

interface GridProposalState {
  hostId: string;
  hostName: string;
  actionId: string;
  incidentId: string;
  lateralTargets: number;
  maxEgressMbps: number;
}

export const FallingBlockGrid: React.FC = () => {
  const [nodes, setNodes] = useState<ThreatNode[]>(INITIAL_NODES);
  const [wsStatus, setWsStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const [proposingId, setProposingId] = useState<string | null>(null);
  const [pendingProposal, setPendingProposal] = useState<GridProposalState | null>(null);
  const [isReviewing, setIsReviewing] = useState(false);
  const [reviewFeedback, setReviewFeedback] = useState<string | null>(null);

  // Fetch live topology directly from FalkorDB on mount
  useEffect(() => {
    authenticatedFetch(`${API_BASE}/api/v1/threat/topology/${TENANT_ID}`)
      .then((r) => r.ok ? r.json() : null)
      .then((data: ThreatNode[] | null) => {
        if (data && data.length > 0) {
          setNodes(data);
        }
      })
      .catch(() => {
        // Fall back to INITIAL_NODES if offline
      });
  }, []);

  // Step 1: Responder proposes containment (does NOT auto-approve)
  const handleProposeContainment = useCallback(async (node: ThreatNode) => {
    setProposingId(node.id);
    setReviewFeedback(`Proposing containment for ${node.name}…`);
    try {
      const propRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/propose`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: `inc-grid-${node.id}-${Date.now()}`,
          target_host_id: node.id,
          tenant_id: TENANT_ID,
          justification: `Interactive Grid Containment: ${node.name} (${node.id})`,
        }),
      });

      if (propRes.ok) {
        const propData = await propRes.json();
        setPendingProposal({
          hostId: node.id,
          hostName: node.name,
          actionId: propData.action_id,
          incidentId: propData.incident_id,
          lateralTargets: propData.risk_assessment?.lateral_targets ?? 14,
          maxEgressMbps: propData.risk_assessment?.max_egress_mbps ?? 43.0,
        });
        setReviewFeedback(`Proposal ${propData.action_id} generated. Awaiting authorized reviewer decision.`);
      } else {
        setReviewFeedback(`Proposal error: HTTP ${propRes.status}`);
      }
    } catch {
      setReviewFeedback("Failed to reach RootMesh backend.");
    } finally {
      setProposingId(null);
    }
  }, []);

  // Step 2: Explicit Reviewer Decision (Approve or Reject)
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
          comment: decision === "APPROVE"
            ? "Authorized review approval from Threat Command Center"
            : "Reviewer rejected containment proposal (fail-closed)",
        }),
      });

      if (!revRes.ok) {
        setReviewFeedback(`Review rejected: HTTP ${revRes.status}`);
        setIsReviewing(false);
        return;
      }

      if (decision === "APPROVE") {
        // Step 3: Execute approved proposal
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
          const severed = auditData.before_after?.paths_severed ?? pendingProposal.lateralTargets;
          const egress = auditData.before_after?.egress_reduction_mbps ?? pendingProposal.maxEgressMbps;
          setNodes((prev) =>
            prev.map((n) => (n.id === pendingProposal.hostId ? { ...n, status: "CONTAINED" } : n))
          );
          setReviewFeedback(
            `✓ APPROVED & CONTAINED (${auditData.containment_type || "GRAPH_TOPOLOGY_SIMULATION"}) · Severed: ${severed} paths · Reduced Egress: ${egress} Mbps`
          );
        } else {
          setReviewFeedback(`Execution failed: HTTP ${execRes.status}`);
        }
      } else {
        // Decision was REJECT
        setReviewFeedback(
          `✕ REJECTED: Containment proposal ${pendingProposal.actionId} for ${pendingProposal.hostName} was rejected. Graph topology unchanged.`
        );
      }
    } catch {
      setReviewFeedback("Error communicating with incident response service.");
    } finally {
      setIsReviewing(false);
      setPendingProposal(null);
    }
  };

  useEffect(() => {
    let ws: WebSocket;
    let retryTimer: ReturnType<typeof setTimeout>;

    const connect = async () => {
      try {
        const url = await getAuthenticatedWebSocketUrl("/ws/threat-stream", TENANT_ID);
        ws = new WebSocket(url);
        ws.onopen = () => setWsStatus("live");
        ws.onclose = () => {
          setWsStatus("offline");
          retryTimer = setTimeout(connect, 3000);
        };
        ws.onerror = () => setWsStatus("offline");
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.event === "INCIDENT_CONTAINMENT_EXECUTED" && data.target_host_id) {
              setNodes((prev) =>
                prev.map((n) => (n.id === data.target_host_id ? { ...n, status: "CONTAINED" } : n))
              );
            } else if (data.event === "ATTACK_PROPAGATION_COMPUTED") {
              setNodes((prev) =>
                prev.map((n) =>
                  n.id !== data.patient_zero && n.status === "SAFE"
                    ? { ...n, status: "INFECTED" }
                    : n
                )
              );
            }
          } catch {}
        };
      } catch {
        setWsStatus("offline");
      }
    };

    connect();
    return () => {
      ws?.close();
      clearTimeout(retryTimer);
    };
  }, []);

  const infected = nodes.filter((n) => n.status === "INFECTED").length;
  const contained = nodes.filter((n) => n.status === "CONTAINED").length;

  return (
    <div className="w-full rounded-2xl border border-indigo-900/40 bg-slate-950/80 backdrop-blur-md p-6 shadow-2xl">
      {/* Header */}
      <div className="flex flex-wrap justify-between items-center mb-4 gap-3">
        <div>
          <h3 className="text-sm font-semibold text-violet-300 uppercase tracking-widest">
            Live Threat Propagation
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">FalkorDB GraphBLAS Real-Time Traversal</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <span className={`flex items-center gap-1.5 ${wsStatus === "live" ? "text-emerald-400" : wsStatus === "connecting" ? "text-amber-400" : "text-rose-400"}`}>
            <span className={`w-2 h-2 rounded-full ${wsStatus === "live" ? "bg-emerald-500 animate-ping" : wsStatus === "connecting" ? "bg-amber-400 animate-pulse" : "bg-rose-500"}`} />
            {wsStatus === "live" ? "RESP Connected" : wsStatus === "connecting" ? "Connecting…" : "Reconnecting…"}
          </span>
          <span className="text-rose-400">⚠ {infected} Infected</span>
          <span className="text-amber-400">🔒 {contained} Contained (GRAPH_TOPOLOGY_SIMULATION)</span>
        </div>
      </div>

      {/* Review Banner if a Proposal is Pending */}
      {pendingProposal && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-4 p-4 rounded-xl bg-slate-900 border border-amber-500/50 shadow-xl space-y-2 text-xs font-mono"
        >
          <div className="flex justify-between items-center">
            <span className="font-bold text-amber-400">
              🛡️ Containment Proposal Review Pending: {pendingProposal.actionId}
            </span>
            <span className="text-[10px] bg-amber-950/80 text-amber-300 px-2 py-0.5 rounded border border-amber-500/40">
              Mode: GRAPH_TOPOLOGY_SIMULATION
            </span>
          </div>
          <div className="text-slate-300 flex flex-wrap gap-4 text-[11px]">
            <span>Target: <strong className="text-white">{pendingProposal.hostName} ({pendingProposal.hostId})</strong></span>
            <span>Sever: <strong className="text-rose-400">{pendingProposal.lateralTargets} paths</strong></span>
            <span>Egress: <strong className="text-amber-400">{pendingProposal.maxEgressMbps} Mbps</strong></span>
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => handleReviewDecision("APPROVE")}
              disabled={isReviewing}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition-all disabled:opacity-50"
            >
              {isReviewing ? "Executing in Graph…" : "✓ Approve & Execute (Admin Role)"}
            </button>
            <button
              onClick={() => handleReviewDecision("REJECT")}
              disabled={isReviewing}
              className="px-3 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-700/50 font-semibold transition-all disabled:opacity-50"
            >
              ✕ Reject Proposal (Fail-Closed)
            </button>
            <button
              onClick={() => setPendingProposal(null)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 transition-all ml-auto"
            >
              Cancel
            </button>
          </div>
        </motion.div>
      )}

      {reviewFeedback && (
        <div className="text-[11px] text-violet-300 font-mono mb-3 bg-violet-950/30 px-3 py-1 rounded border border-violet-800/30">
          {reviewFeedback}
        </div>
      )}

      {/* Block Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        <AnimatePresence>
          {nodes.map((node, index) => (
            <motion.div
              key={node.id}
              initial={{ y: -80, opacity: 0, scale: 0.75 }}
              animate={{ y: 0, opacity: 1, scale: 1 }}
              exit={{ y: 80, opacity: 0 }}
              transition={{ duration: 0.55, delay: index * 0.08, type: "spring", stiffness: 140 }}
              className={`relative p-4 rounded-xl border backdrop-blur-md flex flex-col justify-between h-32 transition-colors duration-500 ${statusStyles[node.status]}`}
            >
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-mono text-slate-500">{node.id}</span>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase ${badgeStyles[node.status]}`}>
                  {node.status === "CONTAINED" ? "CONTAINED (SIM)" : node.status}
                </span>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-100 leading-tight mt-1">{node.name}</p>
                <p className="text-[10px] text-slate-500 font-mono">{node.ip}</p>
              </div>
              <div className="flex justify-between items-center mt-2">
                <span className="text-[10px] text-indigo-400 font-mono">Hop {node.hops}</span>
                {node.status === "INFECTED" && (
                  <button
                    onClick={() => handleProposeContainment(node)}
                    disabled={proposingId === node.id || !!pendingProposal}
                    className="text-[9px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/40 transition-colors disabled:opacity-50"
                  >
                    {proposingId === node.id ? "Proposing…" : "Propose Contain"}
                  </button>
                )}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};
