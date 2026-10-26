"use client";

import React from "react";
import { SignInButton } from "@clerk/nextjs";
import { ProductWalkthroughReplay } from "@/components/ProductWalkthroughReplay";

const API_DOCS_URL = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/docs`
  : "http://localhost:8000/docs";

export function PublicLandingExperience() {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 sm:py-16 space-y-16 sm:space-y-24">
      {/* ── Section A: Editorial Product Hero ────────────────────────────── */}
      <section aria-label="Product Hero" className="relative pt-4 sm:pt-6 max-w-4xl space-y-6">
        <div className="inline-flex flex-wrap items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#82465D]">
          <span className="w-2 h-2 rounded-full bg-[#D26A50] animate-pulse flex-shrink-0" />
          <span className="font-semibold">Graph-Native Threat Memory &amp; Incident Intelligence</span>
        </div>

        <h1 className="text-3xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-[#302B30] leading-[1.12]">
          Understand connected exposure. Investigate threats.{" "}
          <span className="text-[#D26A50]">Coordinate a controlled response.</span>
        </h1>

        <p className="text-base sm:text-lg md:text-xl text-[#645C64] leading-relaxed max-w-3xl">
          RootMesh maps multi-hop attack propagation across network topology, evaluates high-value database exposure and egress bottlenecks, and enforces guarded human-in-the-loop containment.
        </p>

        {/* Clear Primary & Secondary CTAs */}
        <div className="pt-2 flex flex-wrap items-center gap-3 sm:gap-4">
          <SignInButton mode="modal">
            <button
              type="button"
              className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-[#D26A50] hover:bg-[#BE5B42] text-white text-sm font-semibold transition-all shadow-warm-sm hover:shadow-warm-md cursor-pointer"
            >
              <span>🔐 Sign In with Organization</span>
            </button>
          </SignInButton>

          <a
            href="#product-walkthrough"
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-[#FFFFFF] hover:bg-[#F5EFE6] text-[#302B30] text-sm font-semibold border border-[#DFD6C9] transition-all shadow-warm-xs cursor-pointer"
          >
            <span>▶ Explore Interactive Walkthrough</span>
          </a>

          <a
            href={API_DOCS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-mono text-[#645C64] hover:text-[#302B30] px-3 py-2 transition-colors"
          >
            <span>OpenAPI Swagger Reference ↗</span>
          </a>
        </div>
      </section>

      {/* ── Section B: Product Value Narrative (Editorial Asymmetric Layout) ── */}
      <section aria-label="Core Capabilities" className="space-y-8">
        <div className="border-b border-[#DFD6C9] pb-4">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#D26A50]">
            Core Operational Capabilities
          </span>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-[#302B30] mt-1">
            Why Graph Topology Matters in Security Operations
          </h2>
          <p className="text-sm text-[#645C64] mt-1 max-w-2xl">
            Point-in-time endpoint alerts lack contextual connections. RootMesh turns isolated alerts into an actionable map of propagation, exposure, and ownership.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Outcome 1 */}
          <div className="space-y-3 relative pl-6 border-l-2 border-[#D26A50]">
            <span className="text-xs font-mono font-bold text-[#D26A50]">01 / EXPOSURE</span>
            <h3 className="text-lg font-bold text-[#302B30]">
              Understand Connected Exposure
            </h3>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Analyze multi-hop lateral movement pathways using in-memory graph matrix multiplication. Discovers indirect connectivity between peripheral workstations and core infrastructure before attackers pivot.
            </p>
          </div>

          {/* Outcome 2 */}
          <div className="space-y-3 relative pl-6 border-l-2 border-[#82465D]">
            <span className="text-xs font-mono font-bold text-[#82465D]">02 / IMPACT</span>
            <h3 className="text-lg font-bold text-[#302B30]">
              Investigate Potential Impact
            </h3>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Calculate exact reachability to sensitive databases and quantify egress bandwidth risks using network flow capacity analysis. Know precisely what business assets are in jeopardy.
            </p>
          </div>

          {/* Outcome 3 */}
          <div className="space-y-3 relative pl-6 border-l-2 border-[#26694E]">
            <span className="text-xs font-mono font-bold text-[#26694E]">03 / GOVERNANCE</span>
            <h3 className="text-lg font-bold text-[#302B30]">
              Coordinate a Reviewed Response
            </h3>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Connect technical attack paths to organizational teams via Company Brain. Enforce strict separation of duties: Responders formulate mitigation proposals, but containment requires explicit human approval.
            </p>
          </div>
        </div>
      </section>

      {/* ── Section C: Replayable Product Walkthrough ───────────────────── */}
      <section aria-label="Interactive Walkthrough" className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#82465D]">
              Live Demonstration
            </span>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-[#302B30] mt-1">
              From Alert to Reviewed Containment in 5 Steps
            </h2>
          </div>
          <span className="text-xs font-mono text-[#645C64]">
            Replayable conceptual flow · No credentials needed
          </span>
        </div>

        <ProductWalkthroughReplay />
      </section>

      {/* ── Section D: How RootMesh Works (Operational Pipeline) ─────────── */}
      <section aria-label="Operational Architecture" className="space-y-8">
        <div className="border-b border-[#DFD6C9] pb-4">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#D26A50]">
            Operational Workflow
          </span>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-[#302B30] mt-1">
            How an Autonomous Graph Investigation Operates
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-2">
            <span className="text-xs font-mono font-bold text-[#D26A50]">STAGE 1</span>
            <h3 className="text-sm font-bold text-[#302B30]">Asset Selection</h3>
            <p className="text-[11px] text-[#645C64] leading-relaxed">
              Select any inventory node in the communication graph. Validates tenant identity and pulls topology attributes.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-2">
            <span className="text-xs font-mono font-bold text-[#A06316]">STAGE 2</span>
            <h3 className="text-sm font-bold text-[#302B30]">Topology Traversal</h3>
            <p className="text-[11px] text-[#645C64] leading-relaxed">
              Traverses connected network communication edges to compute blast radius, lateral reach, and network bottleneck capacity.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-2">
            <span className="text-xs font-mono font-bold text-[#82465D]">STAGE 3</span>
            <h3 className="text-sm font-bold text-[#302B30]">Ownership Mapping</h3>
            <p className="text-[11px] text-[#645C64] leading-relaxed">
              Company Brain queries map system ownership, on-call contact details, and approved response runbooks.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#26694E]">
            <span className="text-xs font-mono font-bold text-[#26694E]">STAGE 4</span>
            <h3 className="text-sm font-bold text-[#302B30]">Human Gate</h3>
            <p className="text-[11px] text-[#645C64] leading-relaxed">
              Responder proposes containment parameters. System halts and enforces authorized review by an administrator.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-2">
            <span className="text-xs font-mono font-bold text-[#302B30]">STAGE 5</span>
            <h3 className="text-sm font-bold text-[#302B30]">Simulated Execution</h3>
            <p className="text-[11px] text-[#645C64] leading-relaxed">
              Upon approval, executes topological severance in the graph model, verifying severed paths and eliminated risk.
            </p>
          </div>
        </div>
      </section>

      {/* ── Section E: Enterprise Relevance (Who It Is For) ──────────────── */}
      <section aria-label="Enterprise Personas" className="space-y-8">
        <div className="border-b border-[#DFD6C9] pb-4">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#82465D]">
            Target Audience
          </span>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-[#302B30] mt-1">
            Built for Modern Security Operations
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-3">
            <div className="w-10 h-10 rounded-xl bg-[#FBF0ED] border border-[#F3C4B8] flex items-center justify-center text-lg text-[#D26A50]">
              🔍
            </div>
            <h3 className="text-base font-bold text-[#302B30]">Security Analysts</h3>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Quickly triage lateral alerts and evaluate whether a compromised endpoint has viable reach to restricted payroll or customer records.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-3">
            <div className="w-10 h-10 rounded-xl bg-[#F6EDF1] border border-[#E5CDD8] flex items-center justify-center text-lg text-[#82465D]">
              🛡️
            </div>
            <h3 className="text-base font-bold text-[#302B30]">Incident Responders</h3>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Formulate precise containment proposals with calculated blast radii and immediately identify the engineering team on call for the affected host.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs space-y-3">
            <div className="w-10 h-10 rounded-xl bg-[#E8F2EC] border border-[#C5DFD0] flex items-center justify-center text-lg text-[#26694E]">
              📊
            </div>
            <h3 className="text-base font-bold text-[#302B30]">Infrastructure Security Leads</h3>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Review PageRank centrality rankings to discover high-crossroad assets that require tighter network segmentation before an incident occurs.
            </p>
          </div>
        </div>
      </section>

      {/* ── Section F: Trust, Boundaries & Product Safeguards ───────────── */}
      <section aria-label="Trust and Boundaries" className="p-6 sm:p-8 rounded-2xl bg-[#FAF7F2] border border-[#DFD6C9] space-y-6">
        <div>
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#26694E]">
            Trust &amp; Product Boundaries
          </span>
          <h2 className="text-xl sm:text-2xl font-extrabold text-[#302B30] mt-1">
            Enterprise Security Safeguards
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-[#645C64]">
          <div className="space-y-1.5">
            <strong className="text-[#302B30] block font-mono">1. Verified Identity &amp; Tenant Graph Isolation</strong>
            <p className="leading-relaxed">
              Strict Clerk JWT cryptographic signature verification paired with FalkorDB graph namespace partitioning. All Cypher queries are scoped strictly to the authenticated tenant graph key.
            </p>
          </div>

          <div className="space-y-1.5">
            <strong className="text-[#302B30] block font-mono">2. Human-in-the-Loop Safeguards</strong>
            <p className="leading-relaxed">
              Zero unilateral autonomous network changes. The engine formulates proposals; containment requires explicit human review with full separation of duties.
            </p>
          </div>

          <div className="space-y-1.5">
            <strong className="text-[#302B30] block font-mono">3. Graph Topology Simulation Mode</strong>
            <p className="leading-relaxed">
              In current release, containment simulates edge severance in the tenant graph model to verify impact and egress reduction safely without touching production firewalls.
            </p>
          </div>
        </div>
      </section>

      {/* ── Section G: Closing CTA ──────────────────────────────────────── */}
      <section aria-label="Get Started" className="text-center py-8 space-y-5">
        <h2 className="text-2xl sm:text-4xl font-extrabold text-[#302B30]">
          Ready to investigate connected infrastructure risk?
        </h2>
        <p className="text-sm text-[#645C64] max-w-xl mx-auto leading-relaxed">
          Sign in with your organization account to access your tenant graph, analyze active incidents, and coordinate reviewed responses.
        </p>

        <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
          <SignInButton mode="modal">
            <button
              type="button"
              className="px-6 py-3 rounded-xl bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-sm transition-all shadow-warm-sm hover:shadow-warm-md cursor-pointer"
            >
              Sign In to Your Workspace
            </button>
          </SignInButton>

          <a
            href={API_DOCS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="px-5 py-3 rounded-xl bg-[#FFFFFF] hover:bg-[#F5EFE6] text-[#302B30] font-semibold text-sm border border-[#DFD6C9] transition-all cursor-pointer"
          >
            Review OpenAPI Documentation ↗
          </a>
        </div>
      </section>
    </div>
  );
}
