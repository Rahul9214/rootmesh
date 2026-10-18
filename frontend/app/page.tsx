import React from "react";
import { HeroSection } from "@/components/HeroSection";
import { FallingBlockGrid } from "@/components/FallingBlockGrid";
import { SwipeableCardStack } from "@/components/SwipeableCardStack";
import { GraphCanvas } from "@/components/GraphCanvas";

const API_DOCS_URL = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/docs`
  : "http://localhost:8000/docs";

export default function HomePage() {
  return (
    <main className="min-h-screen">
      {/* ── Top Nav Bar ─────────────────────────── */}
      <nav className="sticky top-0 z-50 border-b border-violet-900/30 bg-slate-950/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-violet-600 flex items-center justify-center shadow-[0_0_12px_rgba(139,92,246,0.5)]">
              <span className="text-white text-xs font-black">R</span>
            </div>
            <span className="font-bold text-slate-100 tracking-tight text-base">
              Root<span className="text-gradient-amethyst">Mesh</span>
            </span>
            <span className="hidden sm:block text-[10px] text-slate-600 font-mono border border-slate-800 px-2 py-0.5 rounded">
              FalkorDB GraphBLAS v6
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping inline-block" />
              <span className="hidden sm:inline">RESP:6379</span>
            </span>
            <span className="text-violet-400 bg-violet-950/40 px-2.5 py-0.5 rounded border border-violet-800/30">
              sec_ops_tenant_alpha
            </span>
          </div>
        </div>
      </nav>

      {/* ── Page Content ────────────────────────── */}
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-10">

        {/* ── Hero Command Section ─────────────── */}
        <section aria-label="Threat Command Center">
          <div className="mb-6">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-violet-950/60 border border-violet-500/30 text-[11px] font-mono text-violet-300 mb-2">
              <span>⚡ FalkorDB Graph Hacks 2026</span>
              <span>·</span>
              <span>Tracks 1, 2, 3</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-black tracking-tight text-slate-100">
              Threat{" "}
              <span className="text-gradient-amethyst">Intelligence</span>
              {" "}Command Center
            </h1>
            <p className="text-sm text-slate-400 mt-2 max-w-2xl leading-relaxed">
              FalkorDB GraphBLAS-powered autonomous threat memory & incident response engine.
              Multi-hop path traversals, PageRank asset scoring, and episodic memory persistence in under 5ms.
            </p>
          </div>
          <HeroSection />
        </section>

        {/* ── Two-Column Layout ────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

          {/* ── Live Propagation Grid ─────────── */}
          <section aria-label="Live Threat Propagation">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-widest mb-4">
              Network Topology — Live Propagation
            </h2>
            <FallingBlockGrid />
          </section>

          {/* ── Triage Card Stack ────────────── */}
          <section aria-label="Incident Triage">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-widest mb-4">
              Incident Triage Queue
            </h2>
            <p className="text-xs text-slate-500 mb-4 font-mono">
              Swipe right / click Contain (Graph-Level Sim) · Swipe left to dismiss · Save to FalkorDB episodic memory
            </p>
            <SwipeableCardStack />
          </section>
        </div>

        {/* ── PageRank Asset Ranking ─────────────── */}
        <section aria-label="Critical Asset Rankings">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-widest mb-4">
            Critical Infrastructure Ranking — FalkorDB PageRank
          </h2>
          <div className="max-w-2xl">
            <GraphCanvas />
          </div>
        </section>

      </div>

      {/* ── Footer ──────────────────────────────── */}
      <footer className="border-t border-slate-900 mt-16 px-6 py-6">
        <div className="max-w-7xl mx-auto flex flex-wrap justify-between items-center gap-4 text-xs text-slate-600 font-mono">
          <span>RootMesh — FalkorDB Graph Hacks 2026</span>
          <div className="flex gap-4">
            <a href={API_DOCS_URL} target="_blank" rel="noopener noreferrer" className="hover:text-violet-400 transition-colors">
              FastAPI OpenAPI Docs ↗
            </a>
            <a href="http://localhost:3005" target="_blank" rel="noopener noreferrer" className="hover:text-violet-400 transition-colors">
              FalkorDB Canvas (Port 3005) ↗
            </a>
            <span>Track 1 · Track 2 · Track 3</span>
          </div>
        </div>
      </footer>
    </main>
  );
}
