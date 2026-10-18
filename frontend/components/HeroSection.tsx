"use client";

import React, { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

interface ThreatLevel {
  label: string;
  color: string;
  glow: string;
}

const THREAT_LEVELS: ThreatLevel[] = [
  { label: "CRITICAL",  color: "text-rose-400",   glow: "shadow-[0_0_20px_rgba(244,63,94,0.5)]"   },
  { label: "ELEVATED",  color: "text-amber-400",   glow: "shadow-[0_0_20px_rgba(255,184,0,0.4)]"   },
  { label: "GUARDED",   color: "text-violet-400",  glow: "shadow-[0_0_20px_rgba(139,92,246,0.35)]" },
  { label: "NORMAL",    color: "text-emerald-400", glow: ""                                         },
];

interface TriageResult {
  patient_zero: string;
  target_count: number;
  execution_time_ms: number;
  attack_paths: Array<{ target_name: string; hops: number; path: string[] }>;
}

export const HeroSection: React.FC = () => {
  const [input, setInput] = useState("host-0");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TriageResult | null>(null);
  const [threatLevel, setThreatLevel] = useState(1);
  const [terminalLines, setTerminalLines] = useState<string[]>([
    "[RootMesh] Engine initialized — FalkorDB RESP connected on port 6379",
    "[RootMesh] Threat graph loaded: 8 hosts | 2 CVEs | 1 tenant",
    "[RootMesh] Awaiting triage command…",
  ]);

  const pushLine = useCallback((line: string) => {
    setTerminalLines((prev) => [...prev.slice(-29), line]);
  }, []);

  const runTriage = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    pushLine(`[Triage Agent] Initiating sweep from Patient Zero: ${input}…`);

    try {
      const res = await authenticatedFetch(`${API_BASE}/api/v1/threat/traverse`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: TENANT_ID,
          patient_zero_id: input.trim(),
          max_hops: 4,
        }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: TriageResult = await res.json();
      setResult(data);

      const lvl = data.target_count >= 6 ? 0 : data.target_count >= 3 ? 1 : data.target_count >= 1 ? 2 : 3;
      setThreatLevel(lvl);

      pushLine(`[FalkorDB] Multi-hop traversal complete in ${data.execution_time_ms}ms`);
      pushLine(`[Triage Agent] ${data.target_count} compromised assets identified`);
      data.attack_paths.slice(0, 5).forEach((p) =>
        pushLine(`[Attack Path] Hop ${p.hops}: ${p.path.join(" → ")}`)
      );
      pushLine(`[Memory Agent] Findings persisted to FalkorDB episodic memory.`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      pushLine(`[ERROR] ${msg || "Backend unreachable. Ensure Docker stack is running."}`);
    } finally {
      setLoading(false);
    }
  }, [input, pushLine]);

  const currentThreat = THREAT_LEVELS[threatLevel];

  return (
    <section className="w-full space-y-6">
      {/* Threat Level Banner */}
      <div className={`flex items-center justify-between px-5 py-3 rounded-xl border border-violet-900/40 bg-slate-950/60 backdrop-blur-md ${currentThreat.glow}`}>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 uppercase tracking-widest font-mono">System Threat Level</span>
          <motion.span
            key={currentThreat.label}
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className={`text-lg font-black tracking-wide ${currentThreat.color}`}
          >
            {currentThreat.label}
          </motion.span>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
          FalkorDB: LIVE
        </div>
      </div>

      {/* Action Bar */}
      <div className="flex gap-3">
        <div className="flex-1 relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-violet-500 text-sm font-mono select-none">⌖</span>
          <input
            id="patient-zero-input"
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runTriage()}
            placeholder="Enter Compromised Asset ID (e.g. host-0)"
            className="w-full pl-8 pr-4 py-3 rounded-xl bg-slate-900/80 border border-violet-800/40 text-slate-200 placeholder-slate-600 font-mono text-sm focus:outline-none focus:border-violet-500/70 focus:shadow-[0_0_12px_rgba(139,92,246,0.2)] transition-all"
          />
        </div>
        <motion.button
          id="run-triage-btn"
          onClick={runTriage}
          disabled={loading}
          whileHover={{ scale: 1.04 }}
          whileTap={{ scale: 0.97 }}
          className="px-6 py-3 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-semibold text-sm shadow-[0_0_20px_rgba(139,92,246,0.35)] transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
        >
          {loading ? (
            <span className="flex items-center gap-2">
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
              </svg>
              Analyzing…
            </span>
          ) : "Run Triage"}
        </motion.button>
      </div>

      {/* Terminal Stream */}
      <div className="bg-slate-950/90 border border-slate-800/60 rounded-xl p-4 font-mono text-xs text-emerald-400 h-40 overflow-y-auto scrollbar-thin scrollbar-track-slate-900 scrollbar-thumb-violet-800/50">
        {terminalLines.map((line, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -5 }}
            animate={{ opacity: 1, x: 0 }}
            className="leading-relaxed"
          >
            <span className="text-slate-600 mr-2 select-none">›</span>
            {line}
          </motion.div>
        ))}
      </div>

      {/* Quick Stats */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-3 gap-3"
        >
          {[
            { label: "Compromised Assets",  value: result.target_count,              color: "text-rose-400"   },
            { label: "Traversal Time",       value: `${result.execution_time_ms}ms`,  color: "text-amber-400"  },
            { label: "Attack Paths Found",   value: result.attack_paths.length,       color: "text-violet-400" },
          ].map((s) => (
            <div key={s.label} className="bg-slate-900/60 border border-slate-800/50 rounded-xl p-3 text-center">
              <div className={`text-2xl font-black ${s.color}`}>{s.value}</div>
              <div className="text-[10px] text-slate-500 mt-1 uppercase tracking-wide">{s.label}</div>
            </div>
          ))}
        </motion.div>
      )}
    </section>
  );
};
