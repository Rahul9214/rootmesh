"use client";

import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence, PanInfo } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";
import type { InvestigationSummary } from "./HeroSection";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export interface IncidentCard {
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
  incident_status?: string;
}

const severityBadgeStyles: Record<string, string> = {
  CRITICAL: "bg-[#FBF0ED] text-[#C24128] border border-[#F3C4B8]",
  HIGH:     "bg-[#FDF5E8] text-[#A06316] border border-[#F4DCB6]",
  MEDIUM:   "bg-[#F6EDF1] text-[#82465D] border border-[#E5CDD8]",
};

interface ActiveProposalState {
  card: IncidentCard;
  actionId: string;
  incidentId: string;
  lateralTargets?: number;
  maxEgressMbps?: number;
  proposer: string;
}

export interface SwipeableCardStackProps {
  activeTargetHostId?: string;
  activeInvestigation?: InvestigationSummary | null;
  activeIncidentId?: string;
  onContainmentExecuted?: (auditData: Record<string, unknown>) => void;
  onContainmentRejected?: (actionId: string) => void;
  onProposalCreated?: (proposal: Record<string, unknown>) => void;
  onProposalReviewed?: (decision: "APPROVE" | "REJECT", proposal: Record<string, unknown>) => void;
  onExecutionStarted?: (actionId: string) => void;
  onExecutionFailed?: (error: string) => void;
  onSelectIncident?: (incidentId: string, hostId: string, hostName: string) => void;
  tenantId?: string;
}

export const SwipeableCardStack: React.FC<SwipeableCardStackProps> = ({
  activeTargetHostId,
  activeInvestigation,
  activeIncidentId,
  onContainmentExecuted,
  onContainmentRejected,
  onProposalCreated,
  onProposalReviewed,
  onExecutionStarted,
  onExecutionFailed,
  onSelectIncident,
  tenantId,
}) => {
  const [cards, setCards] = useState<IncidentCard[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState<string[]>([]);
  const [contained, setContained] = useState<string[]>([]);
  const [savingMemory, setSavingMemory] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  // Guarded Review State (Human-in-the-Loop)
  const [activeProposal, setActiveProposal] = useState<ActiveProposalState | null>(null);
  const [isProposing, setIsProposing] = useState(false);
  const [isReviewing, setIsReviewing] = useState(false);

  const requestIdRef = useRef(0);

  // Synchronize top card with activeIncidentId or activeTargetHostId if it exists in current cards
  useEffect(() => {
    if (activeIncidentId || activeTargetHostId) {
      setCards((prev) => {
        const matchIdx = prev.findIndex(
          (c) =>
            (activeIncidentId && c.id === activeIncidentId) ||
            (activeTargetHostId && c.target_host_id === activeTargetHostId)
        );
        if (matchIdx > 0) {
          const matchCard = prev[matchIdx];
          const remaining = prev.filter((_, idx) => idx !== matchIdx);
          return [matchCard, ...remaining];
        }
        return prev;
      });
    }
  }, [activeTargetHostId, activeIncidentId]);

  // Fetch tenant-scoped incidents directly from FalkorDB backend (bounded retrieval)
  useEffect(() => {
    // Reset state whenever the authorized tenant changes
    setCards([]);
    setActiveProposal(null);
    setDismissed([]);
    setContained([]);
    setActionFeedback(null);
    setError(null);

    if (!tenantId) {
      setLoading(false);
      return;
    }

    setLoading(true);
    const thisRequestId = ++requestIdRef.current;

    authenticatedFetch(`${API_BASE}/api/v1/incident/${tenantId}?limit=5`)
      .then(async (res) => {
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data: Record<string, unknown>[]) => {
        // Prevent stale asynchronous responses from updating workspace
        if (thisRequestId !== requestIdRef.current) return;
        if (!Array.isArray(data)) {
          setCards([]);
          return;
        }

        const loadedCards: IncidentCard[] = data.map((item) => {
          const cb = (item.company_brain as Record<string, unknown>) || {};
          const oncallName = cb.oncall_name
            ? `${cb.oncall_name}${cb.oncall_role ? ` (${cb.oncall_role})` : ""}`
            : "Unassigned";
          const runbookTitle = cb.runbook_title
            ? `${cb.runbook_title}${cb.runbook_sla_minutes ? ` (SLA ${cb.runbook_sla_minutes}m)` : ""}`
            : "Incident Response SOP";
          const hostName = (cb.host_name as string) || (item.patient_zero_id as string) || "Workstation-PatientZero";

          const rawSev = typeof item.severity === "string" ? item.severity.toUpperCase() : "";
          const severity: "CRITICAL" | "HIGH" | "MEDIUM" =
            rawSev === "CRITICAL" || rawSev === "HIGH" || rawSev === "MEDIUM"
              ? rawSev
              : "HIGH";

          return {
            id: String(item.incident_id || ""),
            title: String(item.title || `Incident Investigation: ${item.incident_id}`),
            severity,
            target_host: hostName,
            target_host_id: String(item.patient_zero_id || "host-0"),
            owner_team: String(cb.team_name || "SecOps Incident Response"),
            service_name: String(cb.service_name || "Connected Infrastructure Service"),
            oncall: oncallName,
            runbook: runbookTitle,
            hops: 0,
            incident_status: typeof item.status === "string" ? item.status : "INVESTIGATED",
          };
        });

        setCards(loadedCards);
        setError(null);
      })
      .catch((err: unknown) => {
        if (thisRequestId !== requestIdRef.current) return;
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
        setCards([]);
      })
      .finally(() => {
        if (thisRequestId === requestIdRef.current) {
          setLoading(false);
        }
      });
  }, [tenantId]);

  // Merge live completed investigation into top of stack
  useEffect(() => {
    if (!activeInvestigation || !activeInvestigation.incident_id) return;

    const cb = activeInvestigation.company_brain;
    const pzName = activeInvestigation.patient_zero_name || "Workstation-PatientZero";
    const pzId = activeInvestigation.patient_zero_id || "host-0";

    const invCard: IncidentCard = {
      id: activeInvestigation.incident_id,
      title: `Automated Threat Investigation: ${pzName}`,
      severity:
        activeInvestigation.target_count >= 10
          ? "CRITICAL"
          : activeInvestigation.target_count >= 4
          ? "HIGH"
          : "MEDIUM",
      target_host: pzName,
      target_host_id: pzId,
      owner_team: cb?.team_name || "SecOps Incident Response",
      service_name: "Connected Service Gateway",
      oncall: cb?.person_name
        ? `${cb.person_name}${cb.oncall_role ? ` (${cb.oncall_role})` : ""}`
        : "Alex Rivera (Lead Responder)",
      runbook: cb?.runbook_title
        ? `${cb.runbook_title}${cb.runbook_sla_minutes ? ` (SLA ${cb.runbook_sla_minutes}m)` : ""}`
        : "Workstation Lateral Movement SOP",
      hops: 0,
      incident_status: "INVESTIGATED",
    };

    setCards((prev) => {
      const remaining = prev.filter((c) => c.id !== invCard.id);
      return [invCard, ...remaining];
    });
  }, [activeInvestigation]);

  // Step 1: Responder proposes containment (does NOT auto-approve)
  const initiateProposal = async (card: IncidentCard) => {
    if (!tenantId) {
      setActionFeedback("Cannot propose containment: Active tenant session required.");
      return;
    }

    if (!card.id || card.id === "inc-1" || card.id === "inc-latest") {
      setActionFeedback("Cannot propose containment for unverified incident ID.");
      return;
    }

    setIsProposing(true);
    setActionFeedback(`Generating containment proposal for ${card.target_host}…`);

    try {
      const propRes = await authenticatedFetch(`${API_BASE}/api/v1/incident/propose`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: card.id,
          target_host_id: card.target_host_id,
          tenant_id: tenantId,
          justification: `Triage Card Containment Proposal: ${card.title}`,
        }),
      });

      if (propRes.ok) {
        const propData = await propRes.json();
        const lateralTargets =
          typeof propData.risk_assessment?.lateral_targets === "number"
            ? propData.risk_assessment.lateral_targets
            : undefined;
        const maxEgress =
          typeof propData.risk_assessment?.max_egress_mbps === "number"
            ? propData.risk_assessment.max_egress_mbps
            : undefined;

        setActiveProposal({
          card,
          actionId: propData.action_id,
          incidentId: propData.incident_id,
          lateralTargets,
          maxEgressMbps: maxEgress,
          proposer: propData.proposer_principal || "Authenticated Responder",
        });
        onProposalCreated?.(propData);
        setActionFeedback(`Proposal ${propData.action_id} created. Awaiting authorized reviewer decision.`);
      } else {
        const errJson = await propRes.json().catch(() => ({}));
        setActionFeedback(`Proposal error: ${errJson.detail || `HTTP ${propRes.status}`}`);
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
              ? "Explicitly approved by authorized incident reviewer"
              : "Explicitly rejected during human-in-the-loop review (fail-closed)",
        }),
      });

      if (!revRes.ok) {
        const errJson = await revRes.json().catch(() => ({}));
        setActionFeedback(`Review rejected: ${errJson.detail || `HTTP ${revRes.status}`}`);
        setIsReviewing(false);
        return;
      }

      const revData = await revRes.json().catch(() => ({}));
      onProposalReviewed?.(decision, revData);

      if (decision === "APPROVE") {
        // Step 3: Execute approved action
        onExecutionStarted?.(activeProposal.actionId);
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
          const severed =
            auditData.before_after?.paths_severed !== undefined
              ? auditData.before_after.paths_severed
              : activeProposal.lateralTargets;
          const egress =
            auditData.before_after?.egress_reduction_mbps !== undefined
              ? auditData.before_after.egress_reduction_mbps
              : activeProposal.maxEgressMbps;

          const severedText = severed !== undefined ? `Severed: ${severed} paths` : "Paths severed";
          const egressText = egress !== undefined ? `Reduced Egress: ${egress} Mbps` : "Egress reduced";

          setActionFeedback(
            `✓ APPROVED & CONTAINED (${auditData.containment_type || "GRAPH_TOPOLOGY_SIMULATION"}) · ${severedText} · ${egressText}`
          );
          setContained((p) => [...p, activeProposal.card.id]);
          setCards((p) => p.filter((c) => c.id !== activeProposal.card.id));
          onContainmentExecuted?.(auditData);
        } else {
          const errJson = await execRes.json().catch(() => ({}));
          const errDetail = errJson.detail || `HTTP ${execRes.status}`;
          setActionFeedback(`Execution failed: ${errDetail}`);
          onExecutionFailed?.(errDetail);
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
      onExecutionFailed?.("Error communicating with incident response service.");
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
    if (!tenantId) {
      setActionFeedback("Cannot save finding: No authenticated tenant.");
      return;
    }
    setSavingMemory(true);
    try {
      const res = await authenticatedFetch(`${API_BASE}/api/v1/threat/memory/finding`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          host_id: card.target_host_id,
          text: card.title,
          severity: card.severity,
          session_id: card.id,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setActionFeedback(`Episodic memory persisted in FalkorDB: ${data.finding_id}`);
      } else {
        const errJson = await res.json().catch(() => ({}));
        setActionFeedback(`Memory save error: ${errJson.detail || `HTTP ${res.status}`}`);
      }
    } catch {
      setActionFeedback("Failed to save finding to threat memory.");
    } finally {
      setSavingMemory(false);
    }
  };

  // Genuine Loading State
  if (loading && cards.length === 0 && !activeProposal) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs min-h-[310px] space-y-3 font-mono">
        <div className="w-8 h-8 rounded-full border-2 border-[#D26A50] border-t-transparent animate-spin mx-auto" />
        <p className="text-xs text-[#645C64]">Loading tenant incident queue…</p>
      </div>
    );
  }

  // Genuine Error State
  if (error && cards.length === 0 && !activeProposal) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center rounded-2xl bg-[#FFFFFF] border border-[#F3C4B8] shadow-warm-xs min-h-[310px] space-y-2 font-mono">
        <div className="w-10 h-10 rounded-full bg-[#FDF0ED] flex items-center justify-center text-lg text-[#C24128]">
          ⚠️
        </div>
        <p className="text-sm font-bold text-[#C24128]">Incident Queue Unavailable</p>
        <p className="text-xs text-[#645C64] max-w-xs">{error}</p>
      </div>
    );
  }

  // Genuine Empty State (Cleared Queue)
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
          {contained.length > 0 || dismissed.length > 0
            ? `Contained: ${contained.length} | Dismissed: ${dismissed.length}`
            : "No active uncontained incidents in tenant workspace."}
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
              <span>Incident ID:</span>
              <strong className="text-[#302B30]">{activeProposal.incidentId}</strong>
            </div>
            <div className="flex justify-between">
              <span>Target Asset:</span>
              <strong className="text-[#302B30]">
                {activeProposal.card.target_host} ({activeProposal.card.target_host_id})
              </strong>
            </div>
            <div className="flex justify-between">
              <span>Current Status:</span>
              <strong className="text-[#A06316]">Awaiting Authorized Review</strong>
            </div>
            <div className="flex justify-between">
              <span>Action Mode:</span>
              <strong className="text-[#D26A50]">GRAPH_TOPOLOGY_SIMULATION</strong>
            </div>
            <div className="flex justify-between">
              <span>Paths to Sever:</span>
              <strong className="text-[#C24128]">
                {activeProposal.lateralTargets !== undefined
                  ? `${activeProposal.lateralTargets} hops`
                  : "Assessing graph"}
              </strong>
            </div>
            <div className="flex justify-between">
              <span>Egress to Eliminate:</span>
              <strong className="text-[#A06316]">
                {activeProposal.maxEgressMbps !== undefined
                  ? `${activeProposal.maxEgressMbps} Mbps`
                  : "Assessing egress"}
              </strong>
            </div>

            <div className="pt-2 border-t border-[#EEE6DC] text-[10px]">
              <span className="text-[#928992]">Company Brain:</span>{" "}
              <strong className="text-[#302B30]">{activeProposal.card.owner_team}</strong> · {activeProposal.card.oncall}
              <div className="text-[9px] text-[#928992] mt-0.5">
                Proposer: <span className="font-semibold text-[#302B30]">{activeProposal.proposer}</span>
              </div>
            </div>
          </div>

          <div className="flex gap-2 pt-1">
            <button
              onClick={() => handleReviewDecision("APPROVE")}
              disabled={isReviewing}
              className="flex-1 py-2 px-3 rounded-xl bg-[#26694E] hover:bg-[#1E543E] text-white font-semibold text-xs shadow-warm-xs transition-all disabled:opacity-50 cursor-pointer"
            >
              {isReviewing ? "Executing in Graph…" : "✓ Approve & Execute"}
            </button>
            <button
              onClick={() => handleReviewDecision("REJECT")}
              disabled={isReviewing}
              className="py-2 px-3 rounded-xl bg-[#C24128] hover:bg-[#A3351F] text-white font-semibold text-xs shadow-warm-xs transition-all disabled:opacity-50 cursor-pointer"
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
            onClick={() => onSelectIncident?.(c.id, c.target_host_id, c.target_host)}
            className="absolute inset-x-0 bg-[#F5EFE6] border border-[#DFD6C9] rounded-2xl cursor-pointer hover:border-[#82465D] transition-colors"
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
                {card.incident_status && (
                  <div className="flex justify-between">
                    <span className="text-[#928992]">Investigation State:</span>
                    <span className="text-[#82465D] font-bold uppercase">{card.incident_status}</span>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2 pt-2.5 border-t border-[#EEE6DC]">
                <button
                  onClick={() => persistFinding(card)}
                  disabled={savingMemory}
                  className="flex-1 py-1.5 px-3 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] text-[#82465D] border border-[#DFD6C9] text-xs font-semibold font-mono transition-colors disabled:opacity-50 cursor-pointer"
                >
                  {savingMemory ? "Saving…" : "Save Finding (Memory)"}
                </button>
                <button
                  onClick={() => initiateProposal(card)}
                  disabled={isProposing}
                  className="py-1.5 px-3.5 rounded-lg bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-xs shadow-warm-xs transition-colors disabled:opacity-50 cursor-pointer"
                >
                  {isProposing ? "Proposing…" : "Propose Contain"}
                </button>
                <button
                  onClick={() => dismissCard(card)}
                  aria-label="Dismiss alert"
                  className="py-1.5 px-2.5 rounded-lg bg-[#FAF7F2] hover:bg-[#EEE6DC] text-[#645C64] text-xs border border-[#DFD6C9] transition-colors cursor-pointer"
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
