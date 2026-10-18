"use client";

import React, { useState } from "react";
import { motion, AnimatePresence, PanInfo } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

interface IncidentCard {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  target_host: string;
  target_host_id: string;
  owner_team: string;
  service_name: string;
  oncall: string;
  runbook: string;
  hops?: number;
}

const SEED_CARDS: IncidentCard[] = [
  {
    id: "inc-1",
    title: "EternalBlue RCE Infection Vector",
    severity: "CRITICAL",
    target_host: "Workstation-PatientZero",
    target_host_id: "host-0",
    owner_team: "SecOps Incident Response (Demo)",
    service_name: "Corporate Device Gateway (Demo)",
    oncall: "Alex Rivera (Demo)",
    runbook: "Workstation Lateral Movement SOP (Demo)",
    hops: 0,
  },
  {
    id: "inc-2",
    title: "Log4Shell Exploitation Detected",
    severity: "HIGH",
    target_host: "AppServer-Internal",
    target_host_id: "host-1",
    owner_team: "Platform Infrastructure (Demo)",
    service_name: "Internal Application Core API (Demo)",
    oncall: "Elena Rostova (Demo)",
    runbook: "Tier-0 App Server Compromise SOP (Demo)",
    hops: 1,
  },
  {
    id: "inc-3",
    title: "Unsanitized Egress Bandwidth Spike",
    severity: "CRITICAL",
    target_host: "FileBackupServer",
    target_host_id: "host-2",
    owner_team: "Platform Infrastructure (Demo)",
    service_name: "Secure Backup & Archive Service (Demo)",
    oncall: "Elena Rostova (Demo)",
    runbook: "Database Exfiltration SOP (Demo)",
    hops: 1,
  },
  {
    id: "inc-4",
    title: "Lateral Movement via VLAN Router",
    severity: "HIGH",
    target_host: "VLAN-Router",
    target_host_id: "host-3",
    owner_team: "Edge Security (Demo)",
    service_name: "VLAN Routing & SDN Core (Demo)",
    oncall: "Marcus Chen (Demo)",
    runbook: "Network Isolation SOP (Demo)",
    hops: 2,
  },
];

const severityColors = {
  CRITICAL: "text-rose-400 bg-rose-950/60 border-rose-500/30",
  HIGH:     "text-amber-400 bg-amber-950/60 border-amber-500/30",
  MEDIUM:   "text-sky-400 bg-sky-950/60 border-sky-500/30",
};

interface ActiveProposalState {
  card: IncidentCard;
  actionId: string;
  incidentId: string;
  lateralTargets: number;
  maxEgressMbps: number;
  proposer: string;
}

export const SwipeableCardStack: React.FC = () => {
  const [cards, setCards] = useState<IncidentCard[]>(SEED_CARDS);
  const [dismissed, setDismissed] = useState<string[]>([]);
  const [contained, setContained] = useState<string[]>([]);
  const [savingMemory, setSavingMemory] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  // Guarded Review State (Human-in-the-Loop)
  const [activeProposal, setActiveProposal] = useState<ActiveProposalState | null>(null);
  const [isProposing, setIsProposing] = useState(false);
  const [isReviewing, setIsReviewing] = useState(false);

  // Step 1: Responder proposes containment (does NOT auto-approve)
  const initiateProposal = async (card: IncidentCard) => {
    setIsProposing(true);
    setActionFeedback(`Generating containment proposal for ${card.target_host}…`);
    try {
      const propRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/propose`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: card.id,
          target_host_id: card.target_host_id,
          tenant_id: TENANT_ID,
          justification: `Triage Card Containment Proposal: ${card.title}`,
        }),
      });

      if (propRes.ok) {
        const propData = await propRes.json();
        setActiveProposal({
          card,
          actionId: propData.action_id,
          incidentId: propData.incident_id,
          lateralTargets: propData.risk_assessment?.lateral_targets ?? 14,
          maxEgressMbps: propData.risk_assessment?.max_egress_mbps ?? 43.0,
          proposer: propData.proposer_principal ?? "alex.rivera",
        });
        setActionFeedback(`Proposal ${propData.action_id} created. Awaiting authorized reviewer approval.`);
      } else {
        setActionFeedback(`Proposal rejected by server: HTTP ${propRes.status}`);
      }
    } catch {
      setActionFeedback("Failed to reach RootMesh backend to propose containment.");
    } finally {
      setIsProposing(false);
    }
  };

  // Step 2: Authorized Reviewer explicitly Approves or Rejects
  const handleReviewDecision = async (decision: "APPROVE" | "REJECT") => {
    if (!activeProposal) return;
    setIsReviewing(true);

    try {
      // Review endpoint call
      const revRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_id: activeProposal.actionId,
          decision,
          comment: decision === "APPROVE"
            ? "Explicitly approved by SecOps Lead Reviewer"
            : "Explicitly rejected during human-in-the-loop review (fail-closed)",
        }),
      });

      if (!revRes.ok) {
        setActionFeedback(`Review decision rejected: HTTP ${revRes.status}`);
        setIsReviewing(false);
        return;
      }

      if (decision === "APPROVE") {
        // Step 3: Execute approved action with durable idempotency key
        const execRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/execute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action_id: activeProposal.actionId,
            idempotency_key: `card-${activeProposal.card.id}-${Date.now()}`,
          }),
        });

        if (execRes.ok) {
          const auditData = await execRes.json();
          const severed = auditData.before_after?.paths_severed ?? activeProposal.lateralTargets;
          const egress = auditData.before_after?.egress_reduction_mbps ?? activeProposal.maxEgressMbps;
          setActionFeedback(
            `✓ APPROVED & CONTAINED (${auditData.containment_type || "GRAPH_TOPOLOGY_SIMULATION"}) · Severed: ${severed} paths · Reduced Egress: ${egress} Mbps`
          );
          setContained((p) => [...p, activeProposal.card.id]);
          setCards((p) => p.filter((c) => c.id !== activeProposal.card.id));
        } else {
          setActionFeedback(`Execution failed: HTTP ${execRes.status}`);
        }
      } else {
        // Decision was REJECT (fail-closed)
        setActionFeedback(
          `✕ REJECTED: Containment proposal ${activeProposal.actionId} was rejected. Graph topology untouched.`
        );
      }
    } catch {
      setActionFeedback("Error communicating with incident response service.");
    } finally {
      setIsReviewing(false);
      setActiveProposal(null);
    }
  };

  const dismissCard = (card: IncidentCard) => {
    setDismissed((p) => [...p, card.id]);
    setActionFeedback(`Dismissed alert for ${card.target_host}`);
    setCards((p) => p.filter((c) => c.id !== card.id));
  };

  const handleDragEnd = (card: IncidentCard, info: PanInfo) => {
    if (info.offset.x > 100) initiateProposal(card);
    else if (info.offset.x < -100) dismissCard(card);
  };

  const persistFinding = async (card: IncidentCard) => {
    setSavingMemory(true);
    try {
      const res = await authenticatedFetch(`${API_BASE}/api/v1/threat/memory/finding`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: TENANT_ID,
          host_id: card.target_host_id,
          text: card.title,
          severity: card.severity,
          session_id: "dashboard-session",
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setActionFeedback(`Episodic memory saved to FalkorDB: ${data.finding_id}`);
      }
    } finally {
      setSavingMemory(false);
    }
  };

  if (cards.length === 0 && !activeProposal) {
    return (
      <div className="flex flex-col items-center justify-center p-10 text-center border border-violet-900/30 rounded-2xl bg-slate-950/60 min-h-[300px]">
        <div className="text-4xl mb-3">🛡️</div>
        <p className="text-violet-300 font-semibold">All incidents triaged & contained.</p>
        <p className="text-xs text-slate-500 mt-1 font-mono">
          Contained (GRAPH_TOPOLOGY_SIMULATION): {contained.length} | Dismissed: {dismissed.length}
        </p>
        {actionFeedback && (
          <p className="text-[11px] text-emerald-400 mt-3 font-mono bg-emerald-950/40 px-3 py-1 rounded border border-emerald-500/30">
            ✓ {actionFeedback}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="relative w-full max-w-md mx-auto" style={{ minHeight: "330px" }}>
      {actionFeedback && (
        <div className="text-[11px] text-violet-300 font-mono mb-2 text-center bg-violet-950/40 py-1.5 px-3 rounded border border-violet-800/30">
          {actionFeedback}
        </div>
      )}

      {/* Review Modal / Authorization Stage */}
      {activeProposal && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-5 rounded-2xl bg-slate-950 border-2 border-amber-500/60 shadow-2xl space-y-3 z-30"
        >
          <div className="flex justify-between items-center border-b border-amber-500/30 pb-2">
            <span className="text-xs font-black tracking-wider text-amber-400 uppercase font-mono">
              🛡️ Guarded Containment Review
            </span>
            <span className="text-[10px] bg-amber-950 text-amber-300 px-2 py-0.5 rounded font-mono border border-amber-600/40">
              RBAC: Reviewer Required
            </span>
          </div>

          <div className="space-y-1.5 text-xs font-mono text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-500">Proposal ID:</span>
              <span className="text-violet-300">{activeProposal.actionId}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Target Asset:</span>
              <span className="text-slate-200">{activeProposal.card.target_host} ({activeProposal.card.target_host_id})</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Containment Mode:</span>
              <span className="text-amber-400">GRAPH_TOPOLOGY_SIMULATION</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Paths to Sever:</span>
              <span className="text-rose-400">{activeProposal.lateralTargets} lateral hops</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Egress to Eliminate:</span>
              <span className="text-amber-400">{activeProposal.maxEgressMbps} Mbps</span>
            </div>
            <div className="pt-2 border-t border-slate-800/80 text-[10px] text-slate-400">
              <span className="text-slate-500">Company Brain:</span> {activeProposal.card.owner_team} · {activeProposal.card.oncall}
              <div className="text-[9px] text-slate-600 mt-0.5">* Synthetic demonstration context in FalkorDB</div>
            </div>
          </div>

          <div className="flex gap-2 pt-2">
            <button
              onClick={() => handleReviewDecision("APPROVE")}
              disabled={isReviewing}
              className="flex-1 py-2 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs shadow-lg transition-all disabled:opacity-50"
            >
              {isReviewing ? "Executing in Graph…" : "✓ Approve & Execute Containment"}
            </button>
            <button
              onClick={() => handleReviewDecision("REJECT")}
              disabled={isReviewing}
              className="py-2 px-3 rounded-xl bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-700/50 text-xs font-semibold transition-all disabled:opacity-50"
            >
              ✕ Reject (Fail-Closed)
            </button>
          </div>
        </motion.div>
      )}

      {/* Background stack shadow */}
      {!activeProposal && cards.slice(1, 3).map((c, i) => (
        <div
          key={c.id + "-shadow"}
          className="absolute inset-x-0 bg-slate-900/60 border border-violet-900/20 rounded-2xl"
          style={{
            top: `${(i + 1) * 10}px`,
            left: `${(i + 1) * 6}px`,
            right: `${(i + 1) * 6}px`,
            bottom: 0,
            opacity: 0.5 - i * 0.15,
            zIndex: 10 - i,
          }}
        />
      ))}

      {/* Top card */}
      {!activeProposal && (
        <AnimatePresence>
          {cards.slice(0, 1).map((card) => (
            <motion.div
              key={card.id}
              drag="x"
              dragConstraints={{ left: 0, right: 0 }}
              dragElastic={0.7}
              onDragEnd={(_, info) => handleDragEnd(card, info)}
              initial={{ scale: 0.95, opacity: 0, y: 10 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ x: 300, opacity: 0 }}
              transition={{ type: "spring", stiffness: 260, damping: 20 }}
              className="absolute inset-x-0 top-0 p-5 rounded-2xl bg-slate-900/90 border border-violet-800/40 backdrop-blur-xl shadow-2xl cursor-grab active:cursor-grabbing select-none"
              style={{ zIndex: 20 }}
            >
              {/* Card Header */}
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-violet-950 text-violet-300 border border-violet-800/40">
                  {card.id}
                </span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${severityColors[card.severity]}`}>
                  {card.severity}
                </span>
              </div>

              {/* Title */}
              <h4 className="text-sm font-semibold text-slate-100 leading-snug mb-2">{card.title}</h4>

              {/* Company Brain Context */}
              <div className="space-y-1 text-xs text-slate-400 font-mono mb-3">
                <div className="flex justify-between">
                  <span className="text-slate-600">Asset:</span>
                  <span className="text-violet-300">{card.target_host} ({card.target_host_id})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600">Company Brain Service:</span>
                  <span className="text-slate-300">{card.service_name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600">On-Call Lead:</span>
                  <span className="text-slate-300">{card.oncall}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600">SOP Runbook:</span>
                  <span className="text-slate-300">{card.runbook}</span>
                </div>
                {card.hops !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-slate-600">Graph Distance:</span>
                    <span className="text-amber-400">{card.hops} hops from Patient Zero</span>
                  </div>
                )}
                <div className="text-[9px] text-slate-600 italic">
                  * Company Brain records are synthetic demonstration data for hackathon evaluation.
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => persistFinding(card)}
                  disabled={savingMemory}
                  className="flex-1 py-1.5 px-3 rounded-lg bg-violet-950/80 hover:bg-violet-900/80 text-violet-300 border border-violet-700/40 text-xs font-medium transition-colors disabled:opacity-50"
                >
                  {savingMemory ? "Saving to Graph…" : "Save Finding (Memory)"}
                </button>
                <button
                  onClick={() => initiateProposal(card)}
                  disabled={isProposing}
                  className="py-1.5 px-3 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-medium transition-colors disabled:opacity-50"
                >
                  {isProposing ? "Proposing…" : "Propose Containment"}
                </button>
                <button
                  onClick={() => dismissCard(card)}
                  className="py-1.5 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs transition-colors"
                >
                  ✕
                </button>
              </div>

              {/* Gesture Hint */}
              <div className="mt-2.5 flex justify-between text-[10px] text-slate-600 font-mono">
                <span>← Swipe left: Dismiss</span>
                <span>Swipe right: Propose Containment →</span>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      )}
    </div>
  );
};
