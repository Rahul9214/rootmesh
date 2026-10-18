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
    title: "EternalBlue RCE Lateral Infection Vector",
    severity: "CRITICAL",
    target_host: "Workstation-PatientZero",
    target_host_id: "host-0",
    owner_team: "SecOps Incident Response",
    service_name: "Corporate Device Gateway",
    oncall: "Alex Rivera (Lead Responder)",
    runbook: "Workstation Lateral Movement SOP (SLA 15m)",
    hops: 0,
  },
  {
    id: "inc-2",
    title: "Log4Shell Exploitation in App Core API",
    severity: "HIGH",
    target_host: "AppServer-Internal",
    target_host_id: "host-1",
    owner_team: "Platform Infrastructure",
    service_name: "Internal Application Core API",
    oncall: "Elena Rostova (Staff Architect)",
    runbook: "Tier-0 App Compromise SOP (SLA 30m)",
    hops: 1,
  },
  {
    id: "inc-3",
    title: "Unsanitized Egress Bandwidth Spike",
    severity: "CRITICAL",
    target_host: "FileBackupServer",
    target_host_id: "host-2",
    owner_team: "Platform Infrastructure",
    service_name: "Secure Backup & Archive Service",
    oncall: "Elena Rostova (Staff Architect)",
    runbook: "Database Exfiltration Mitigation SOP (SLA 10m)",
    hops: 1,
  },
  {
    id: "inc-4",
    title: "VLAN Router Hop Propagation",
    severity: "HIGH",
    target_host: "VLAN-Router",
    target_host_id: "host-3",
    owner_team: "Edge Security",
    service_name: "VLAN Routing & SDN Core",
    oncall: "Marcus Chen (Edge Engineer)",
    runbook: "Network Isolation SOP (SLA 20m)",
    hops: 2,
  },
];

const severityBadgeStyles: Record<string, string> = {
  CRITICAL: "bg-[#FBF0ED] text-[#C24128] border border-[#F3C4B8]",
  HIGH:     "bg-[#FDF5E8] text-[#A06316] border border-[#F4DCB6]",
  MEDIUM:   "bg-[#F6EDF1] text-[#82465D] border border-[#E5CDD8]",
};

interface ActiveProposalState {
  card: IncidentCard;
  actionId: string;
  incidentId: string;
  lateralTargets: number;
  maxEgressMbps: number;
  proposer: string;
}

export interface SwipeableCardStackProps {
  activeTargetHostId?: string;
  onContainmentExecuted?: (auditData: Record<string, unknown>) => void;
  onContainmentRejected?: (actionId: string) => void;
}

export const SwipeableCardStack: React.FC<SwipeableCardStackProps> = ({
  activeTargetHostId = "host-0",
  onContainmentExecuted,
  onContainmentRejected,
}) => {
  const [cards, setCards] = useState<IncidentCard[]>(SEED_CARDS);
  const [dismissed, setDismissed] = useState<string[]>([]);
  const [contained, setContained] = useState<string[]>([]);
  const [savingMemory, setSavingMemory] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  // Synchronize top card with activeTargetHostId if it exists in seed cards
  React.useEffect(() => {
    if (activeTargetHostId) {
      setCards((prev) => {
        const matchIdx = prev.findIndex((c) => c.target_host_id === activeTargetHostId);
        if (matchIdx > 0) {
          const matchCard = prev[matchIdx];
          const remaining = prev.filter((_, idx) => idx !== matchIdx);
          return [matchCard, ...remaining];
        }
        return prev;
      });
    }
  }, [activeTargetHostId]);

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
        setActionFeedback(`Proposal ${propData.action_id} created. Awaiting authorized reviewer decision.`);
      } else {
        setActionFeedback(`Proposal error: HTTP ${propRes.status}`);
      }
    } catch {
      setActionFeedback("Failed to reach RootMesh incident service.");
    } finally {
      setIsProposing(false);
    }
  };

  // Step 2: Explicit Reviewer Decision (Approve or Reject)
  const handleReviewDecision = async (decision: "APPROVE" | "REJECT") => {
    if (!activeProposal) return;
    setIsReviewing(true);

    try {
      const revRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_id: activeProposal.actionId,
          decision,
          comment:
            decision === "APPROVE"
              ? "Explicitly approved by SecOps Incident Lead"
              : "Explicitly rejected during human-in-the-loop review (fail-closed)",
        }),
      });

      if (!revRes.ok) {
        setActionFeedback(`Review rejected: HTTP ${revRes.status}`);
        setIsReviewing(false);
        return;
      }

      if (decision === "APPROVE") {
        // Step 3: Execute approved action
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
          onContainmentExecuted?.(auditData);
        } else {
          setActionFeedback(`Execution failed: HTTP ${execRes.status}`);
        }
      } else {
        // Decision was REJECT (fail-closed)
        setActionFeedback(
          `✕ REJECTED: Containment proposal ${activeProposal.actionId} was rejected. Graph topology untouched.`
        );
        onContainmentRejected?.(activeProposal.actionId);
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
    if (info.offset.x > 90) initiateProposal(card);
    else if (info.offset.x < -90) dismissCard(card);
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
          session_id: "triage-deck-session",
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setActionFeedback(`Episodic memory persisted in FalkorDB: ${data.finding_id}`);
      }
    } finally {
      setSavingMemory(false);
    }
  };

  if (cards.length === 0 && !activeProposal) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs min-h-[310px]">
        <div className="w-12 h-12 rounded-full bg-[#E8F2EC] flex items-center justify-center text-xl text-[#26694E] mb-3">
          ✓
        </div>
        <p className="text-sm font-bold text-[#302B30] font-mono uppercase tracking-wide">
          Incident Triage Queue Cleared
        </p>
        <p className="text-xs text-[#645C64] mt-1 font-mono">
          Contained (GRAPH_TOPOLOGY_SIMULATION): {contained.length} | Dismissed: {dismissed.length}
        </p>
        {actionFeedback && (
          <p className="text-[11px] text-[#26694E] mt-3 font-mono bg-[#E8F2EC] px-3 py-1.5 rounded-lg border border-[#C5DFD0]">
            {actionFeedback}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="relative w-full max-w-md mx-auto" style={{ minHeight: "350px" }}>
      {actionFeedback && (
        <div className="text-[11px] text-[#302B30] font-mono mb-2 text-center bg-[#F5EFE6] py-1.5 px-3 rounded-xl border border-[#DFD6C9]">
          {actionFeedback}
        </div>
      )}

      {/* ── Active Guarded Review Panel (Human-in-the-Loop) ──────────── */}
      {activeProposal && (
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-5 rounded-2xl bg-[#FFFFFF] border-2 border-[#E6A548] shadow-warm-md space-y-3 z-30"
        >
          <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-2">
            <span className="text-xs font-bold text-[#302B30] uppercase font-mono tracking-wider">
              🛡️ Containment Review
            </span>
            <span className="text-[10px] bg-[#FDF5E8] text-[#A06316] font-bold px-2 py-0.5 rounded-md font-mono border border-[#F4DCB6]">
              RBAC: Reviewer Required
            </span>
          </div>

          <div className="space-y-1.5 text-xs font-mono text-[#645C64]">
            <div className="flex justify-between">
              <span>Proposal ID:</span>
              <strong className="text-[#82465D]">{activeProposal.actionId}</strong>
            </div>
            <div className="flex justify-between">
              <span>Target Asset:</span>
              <strong className="text-[#302B30]">
                {activeProposal.card.target_host} ({activeProposal.card.target_host_id})
              </strong>
            </div>
            <div className="flex justify-between">
              <span>Mode:</span>
              <strong className="text-[#D26A50]">GRAPH_TOPOLOGY_SIMULATION</strong>
            </div>
            <div className="flex justify-between">
              <span>Paths to Sever:</span>
              <strong className="text-[#C24128]">{activeProposal.lateralTargets} hops</strong>
            </div>
            <div className="flex justify-between">
              <span>Egress to Eliminate:</span>
              <strong className="text-[#A06316]">{activeProposal.maxEgressMbps} Mbps</strong>
            </div>

            <div className="pt-2 border-t border-[#EEE6DC] text-[10px]">
              <span className="text-[#928992]">Company Brain:</span>{" "}
              <strong className="text-[#302B30]">{activeProposal.card.owner_team}</strong> · {activeProposal.card.oncall}
              <div className="text-[9px] text-[#928992] mt-0.5 italic">
                * Synthetic demonstration context in FalkorDB
              </div>
            </div>
          </div>

          <div className="flex gap-2 pt-1">
            <button
              onClick={() => handleReviewDecision("APPROVE")}
              disabled={isReviewing}
              className="flex-1 py-2 px-3 rounded-xl bg-[#26694E] hover:bg-[#1E543E] text-white font-semibold text-xs shadow-warm-xs transition-all disabled:opacity-50"
            >
              {isReviewing ? "Executing in Graph…" : "✓ Approve & Execute"}
            </button>
            <button
              onClick={() => handleReviewDecision("REJECT")}
              disabled={isReviewing}
              className="py-2 px-3 rounded-xl bg-[#C24128] hover:bg-[#A3351F] text-white font-semibold text-xs shadow-warm-xs transition-all disabled:opacity-50"
            >
              ✕ Reject (Fail-Closed)
            </button>
          </div>
        </motion.div>
      )}

      {/* ── Background Shadow Cards ──────────────────────────────────── */}
      {!activeProposal &&
        cards.slice(1, 3).map((c, i) => (
          <div
            key={c.id + "-shadow"}
            className="absolute inset-x-0 bg-[#F5EFE6] border border-[#DFD6C9] rounded-2xl"
            style={{
              top: `${(i + 1) * 8}px`,
              left: `${(i + 1) * 6}px`,
              right: `${(i + 1) * 6}px`,
              bottom: 0,
              opacity: 0.6 - i * 0.2,
              zIndex: 10 - i,
            }}
          />
        ))}

      {/* ── Top Incident Card ────────────────────────────────────────── */}
      {!activeProposal && (
        <AnimatePresence>
          {cards.slice(0, 1).map((card) => (
            <motion.div
              key={card.id}
              drag="x"
              dragConstraints={{ left: 0, right: 0 }}
              dragElastic={0.65}
              onDragEnd={(_, info) => handleDragEnd(card, info)}
              initial={{ scale: 0.96, opacity: 0, y: 10 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ x: 260, opacity: 0 }}
              transition={{ type: "spring", stiffness: 240, damping: 22 }}
              className="absolute inset-x-0 top-0 p-5 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-sm cursor-grab active:cursor-grabbing select-none"
              style={{ zIndex: 20 }}
            >
              {/* Header */}
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#F5EFE6] text-[#82465D] border border-[#DFD6C9]">
                  {card.id}
                </span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${severityBadgeStyles[card.severity]}`}>
                  {card.severity}
                </span>
              </div>

              {/* Title */}
              <h4 className="text-sm font-bold text-[#302B30] leading-snug mb-2 font-mono">
                {card.title}
              </h4>

              {/* Context Details */}
              <div className="space-y-1 text-xs text-[#645C64] font-mono mb-3">
                <div className="flex justify-between">
                  <span className="text-[#928992]">Target Asset:</span>
                  <span className="text-[#302B30] font-semibold">{card.target_host} ({card.target_host_id})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#928992]">Connected Service:</span>
                  <span className="text-[#302B30]">{card.service_name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#928992]">On-Call Engineer:</span>
                  <span className="text-[#82465D] font-medium">{card.oncall}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#928992]">SOP Playbook:</span>
                  <span className="text-[#A06316] font-medium">{card.runbook}</span>
                </div>
                {card.hops !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-[#928992]">Graph Distance:</span>
                    <span className="text-[#C24128] font-bold">{card.hops} hops</span>
                  </div>
                )}
                <div className="text-[9px] text-[#928992] pt-1 italic">
                  * Company Brain records are synthetic demonstration data for hackathon evaluation.
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2 pt-2.5 border-t border-[#EEE6DC]">
                <button
                  onClick={() => persistFinding(card)}
                  disabled={savingMemory}
                  className="flex-1 py-1.5 px-3 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] text-[#82465D] border border-[#DFD6C9] text-xs font-semibold font-mono transition-colors disabled:opacity-50"
                >
                  {savingMemory ? "Saving…" : "Save Finding (Memory)"}
                </button>
                <button
                  onClick={() => initiateProposal(card)}
                  disabled={isProposing}
                  className="py-1.5 px-3.5 rounded-lg bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-xs shadow-warm-xs transition-colors disabled:opacity-50"
                >
                  {isProposing ? "Proposing…" : "Propose Contain"}
                </button>
                <button
                  onClick={() => dismissCard(card)}
                  aria-label="Dismiss alert"
                  className="py-1.5 px-2.5 rounded-lg bg-[#FAF7F2] hover:bg-[#EEE6DC] text-[#645C64] text-xs border border-[#DFD6C9] transition-colors"
                >
                  ✕
                </button>
              </div>

              <div className="mt-2.5 flex justify-between text-[10px] text-[#928992] font-mono">
                <span>← Swipe to Dismiss</span>
                <span>Swipe to Propose →</span>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      )}
    </div>
  );
};
