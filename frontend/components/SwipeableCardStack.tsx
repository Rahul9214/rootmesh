"use client";

import React, { useState } from "react";
import { motion, AnimatePresence, PanInfo } from "framer-motion";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

interface IncidentCard {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  target_host: string;
  target_host_id: string;
  owner_team: string;
  hops?: number;
}

const SEED_CARDS: IncidentCard[] = [
  { id: "inc-1", title: "EternalBlue RCE Infection Vector",        severity: "CRITICAL", target_host: "Workstation-PatientZero", target_host_id: "host-0", owner_team: "SecOps IR",       hops: 0 },
  { id: "inc-2", title: "Log4Shell Exploitation Detected",          severity: "HIGH",     target_host: "AppServer-Internal",      target_host_id: "host-1", owner_team: "Engineering Lead", hops: 1 },
  { id: "inc-3", title: "Unsanitized Egress Bandwidth Spike",       severity: "CRITICAL", target_host: "FileBackupServer",         target_host_id: "host-2", owner_team: "Infrastructure",   hops: 1 },
  { id: "inc-4", title: "Lateral Movement via VLAN Router",         severity: "HIGH",     target_host: "VLAN-Router",              target_host_id: "host-3", owner_team: "NetOps",           hops: 2 },
];

const severityColors = {
  CRITICAL: "text-rose-400 bg-rose-950/60 border-rose-500/30",
  HIGH:     "text-amber-400 bg-amber-950/60 border-amber-500/30",
  MEDIUM:   "text-sky-400 bg-sky-950/60 border-sky-500/30",
};

export const SwipeableCardStack: React.FC = () => {
  const [cards, setCards] = useState<IncidentCard[]>(SEED_CARDS);
  const [dismissed, setDismissed] = useState<string[]>([]);
  const [contained, setContained] = useState<string[]>([]);
  const [savingMemory, setSavingMemory] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const removeCard = async (card: IncidentCard, action: "CONTAIN" | "DISMISS") => {
    if (action === "CONTAIN") {
      setContained((p) => [...p, card.id]);
      // Real backend containment call in FalkorDB
      try {
        await fetch(`${API_BASE}/api/v1/threat/contain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tenant_id: TENANT_ID, host_id: card.target_host_id }),
        });
        setActionFeedback(`Contained ${card.target_host} in FalkorDB (Graph Sim)`);
      } catch {
        // Fallback feedback
      }
    } else {
      setDismissed((p) => [...p, card.id]);
      setActionFeedback(`Dismissed alert for ${card.target_host}`);
    }
    setCards((p) => p.filter((c) => c.id !== card.id));
  };

  const handleDragEnd = (card: IncidentCard, info: PanInfo) => {
    if (info.offset.x > 100)  removeCard(card, "CONTAIN");
    else if (info.offset.x < -100) removeCard(card, "DISMISS");
  };

  const persistFinding = async (card: IncidentCard) => {
    setSavingMemory(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/threat/memory/finding`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: TENANT_ID,
          host_id:   card.target_host_id,
          text:      card.title,
          severity:  card.severity,
          session_id: "dashboard-session",
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setActionFeedback(`Episodic memory saved: ${data.finding_id}`);
      }
    } finally {
      setSavingMemory(false);
    }
    removeCard(card, "CONTAIN");
  };

  if (cards.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-10 text-center border border-violet-900/30 rounded-2xl bg-slate-950/60 min-h-[260px]">
        <div className="text-4xl mb-3">🛡️</div>
        <p className="text-violet-300 font-semibold">All incidents triaged & contained.</p>
        <p className="text-xs text-slate-500 mt-1 font-mono">
          Contained (Graph Sim): {contained.length} | Dismissed: {dismissed.length}
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
    <div className="relative w-full max-w-md mx-auto" style={{ height: "290px" }}>
      {actionFeedback && (
        <div className="text-[11px] text-violet-300 font-mono mb-2 text-center bg-violet-950/40 py-1 rounded border border-violet-800/30">
          ✓ {actionFeedback}
        </div>
      )}

      {/* Background stack shadow */}
      {cards.slice(1, 3).map((c, i) => (
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
            className="absolute inset-x-0 top-0 p-6 rounded-2xl bg-slate-900/90 border border-violet-800/40 backdrop-blur-xl shadow-2xl cursor-grab active:cursor-grabbing select-none"
            style={{ zIndex: 20 }}
          >
            {/* Card Header */}
            <div className="flex justify-between items-center mb-3">
              <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-violet-950 text-violet-300 border border-violet-800/40">
                {card.id}
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${severityColors[card.severity]}`}>
                {card.severity}
              </span>
            </div>

            {/* Title */}
            <h4 className="text-sm font-semibold text-slate-100 leading-snug mb-3">{card.title}</h4>

            {/* Metadata */}
            <div className="space-y-1.5 text-xs text-slate-400 font-mono mb-4">
              <div className="flex justify-between">
                <span className="text-slate-600">Compromised Asset:</span>
                <span className="text-violet-300">{card.target_host} ({card.target_host_id})</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-600">Owner Team:</span>
                <span className="text-slate-300">{card.owner_team}</span>
              </div>
              {card.hops !== undefined && (
                <div className="flex justify-between">
                  <span className="text-slate-600">Graph Distance:</span>
                  <span className="text-amber-400">{card.hops} hops from Patient Zero</span>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => persistFinding(card)}
                disabled={savingMemory}
                className="flex-1 py-1.5 px-3 rounded-lg bg-violet-950/80 hover:bg-violet-900/80 text-violet-300 border border-violet-700/40 text-xs font-medium transition-colors disabled:opacity-50"
              >
                {savingMemory ? "Saving to Graph…" : "Save to Memory (Track 2)"}
              </button>
              <button
                onClick={() => removeCard(card, "CONTAIN")}
                className="py-1.5 px-3 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-medium transition-colors"
              >
                Contain (Sim)
              </button>
              <button
                onClick={() => removeCard(card, "DISMISS")}
                className="py-1.5 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs transition-colors"
              >
                ✕
              </button>
            </div>

            {/* Gesture Hint */}
            <div className="mt-3 flex justify-between text-[10px] text-slate-600 font-mono">
              <span>← Swipe left: Dismiss</span>
              <span>Swipe right: Contain (Sim) →</span>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};
