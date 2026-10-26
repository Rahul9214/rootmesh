"use client";

import React, { useState } from "react";
import type { IncidentLifecycleState } from "@/components/IncidentJourneyTimeline";

export interface LifecycleGovernanceGuideProps {
  lifecycleState: IncidentLifecycleState;
  hasProposal: boolean;
  hasReview: boolean;
  hasExecution: boolean;
  reviewDecision?: "APPROVE" | "REJECT" | "EXPIRED" | null;
}

export function LifecycleGovernanceGuide({
  lifecycleState,
  hasProposal,
  hasReview,
  hasExecution,
  reviewDecision,
}: LifecycleGovernanceGuideProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);

  // Derive truthful current gate status
  let statusBanner = {
    badge: "STAGE 1–3 COMPLETE · AWAITING PROPOSAL",
    badgeColor: "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]",
    message: "Investigation findings verified. Stages 4–8 remain pending until an authorized proposal is formulated.",
  };

  if (lifecycleState === "PROPOSAL_CREATED") {
    statusBanner = {
      badge: "STAGE 4 SUBMITTED · HUMAN REVIEW REQUIRED",
      badgeColor: "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]",
      message: "Containment proposal formulated. Awaiting explicit approval from an authorized reviewer (Stage 5 Gate).",
    };
  } else if (lifecycleState === "APPROVED") {
    statusBanner = {
      badge: "STAGE 5 APPROVED · READY FOR EXECUTION",
      badgeColor: "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]",
      message: "Human review passed. Authorized for execution in Graph Topology Simulation Mode.",
    };
  } else if (lifecycleState === "CONTAINED") {
    statusBanner = {
      badge: "STAGES 6–8 VERIFIED · SIMULATION CONTAINED",
      badgeColor: "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]",
      message: "Topological isolation simulated and verified. Audit record durably persisted in tenant graph memory.",
    };
  } else if (lifecycleState === "REJECTED" || reviewDecision === "REJECT") {
    statusBanner = {
      badge: "STAGE 5 REJECTED · FAIL-CLOSED ENFORCEMENT",
      badgeColor: "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]",
      message: "Reviewer rejected the mitigation proposal. Execution strictly blocked under zero-trust policy.",
    };
  } else if (lifecycleState === "EXPIRED" || reviewDecision === "EXPIRED") {
    statusBanner = {
      badge: "STAGE 4 EXPIRED · PROPOSAL TIMED OUT",
      badgeColor: "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]",
      message: "Mitigation proposal exceeded its TTL without review. Execution blocked until re-evaluated.",
    };
  } else if (lifecycleState === "EXECUTION_FAILED") {
    statusBanner = {
      badge: "STAGE 6 FAILED · CONTAINMENT ABORTED",
      badgeColor: "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]",
      message: "Topology update encountered an error. State rolled back safely without partial modifications.",
    };
  }

  return (
    <div className="mb-4 rounded-xl border border-[#DFD6C9] bg-[#FFFFFF] shadow-warm-xs overflow-hidden">
      {/* ── Status Banner ────────────────────────────────────────────── */}
      <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3 bg-[#FAF7F2] border-b border-[#EEE6DC]">
        <div className="flex items-center gap-2.5">
          <span className="text-sm">🛡️</span>
          <div>
            <span className="text-xs font-mono font-bold text-[#302B30]">
              Lifecycle Governance Gate
            </span>
            <p className="text-[11px] text-[#645C64]">{statusBanner.message}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border ${statusBanner.badgeColor}`}>
            {statusBanner.badge}
          </span>

          <button
            type="button"
            onClick={() => setDetailsOpen((prev) => !prev)}
            className="text-[11px] font-mono text-[#82465D] hover:text-[#302B30] underline px-2 py-0.5 cursor-pointer"
            aria-expanded={detailsOpen}
          >
            {detailsOpen ? "Hide Criteria ▲" : "View Stage Requirements ▼"}
          </button>
        </div>
      </div>

      {/* ── Collapsible Requirements Disclosure ───────────────────────── */}
      {detailsOpen && (
        <div className="p-4 sm:p-5 bg-[#FFFFFF] text-xs space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Automated Stages (1-3) */}
            <div className="p-3.5 rounded-lg bg-[#FAF7F2] border border-[#EEE6DC] space-y-2">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#D26A50] block">
                Automated Incident Stages (1–3)
              </span>
              <ul className="space-y-1.5 text-[11px] text-[#645C64]">
                <li>
                  <strong className="text-[#302B30]">1. Detection:</strong> Ingests network anomaly or patient-zero inventory node.
                </li>
                <li>
                  <strong className="text-[#302B30]">2. Investigation:</strong> Traces variable-depth Cypher traversal paths in FalkorDB.
                </li>
                <li>
                  <strong className="text-[#302B30]">3. Evidence:</strong> Records lateral blast radius, sensitive database reach, and Company Brain owner.
                </li>
              </ul>
            </div>

            {/* Guarded Stages (4-8) */}
            <div className="p-3.5 rounded-lg bg-[#FAF7F2] border border-[#EEE6DC] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#82465D] block">
                  Guarded Human Governance Stages (4–8)
                </span>
                <span className="text-[10px] font-mono text-[#82465D] bg-[#F6EDF1] px-1.5 py-0.5 rounded border border-[#E5CDD8]">
                  {hasExecution ? "3/3 Gates Cleared" : hasReview ? "2/3 Gates Cleared" : hasProposal ? "1/3 Gates Cleared" : "0/3 Gates Cleared"}
                </span>
              </div>
              <ul className="space-y-1.5 text-[11px] text-[#645C64]">
                <li>
                  <strong className="text-[#302B30]">4. Proposal:</strong> Requires a real persisted proposal specifying severed paths and egress reduction.
                </li>
                <li>
                  <strong className="text-[#302B30]">5. Human Review:</strong> Requires an authorized human reviewer to approve or reject. Never auto-approved.
                </li>
                <li>
                  <strong className="text-[#302B30]">6. Execution:</strong> Executes edge severance in the tenant graph model upon approval; fails closed if rejected.
                </li>
                <li>
                  <strong className="text-[#302B30]">7. Verification:</strong> Confirms post-severance graph topology with zero reachable database paths.
                </li>
                <li>
                  <strong className="text-[#302B30]">8. Memory &amp; Audit:</strong> Records verified containment audit log in tenant graph memory.
                </li>
              </ul>
            </div>
          </div>

          <div className="text-[10px] font-mono text-[#928992] pt-1 border-t border-[#EEE6DC]">
            Safety Guarantee: Pending stages do not advance by time or animation alone. Each stage requires verified backend operation.
          </div>
        </div>
      )}
    </div>
  );
}
