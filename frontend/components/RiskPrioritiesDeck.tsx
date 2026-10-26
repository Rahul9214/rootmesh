"use client";

import React, { useState, useEffect, useCallback } from "react";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export interface PageRankAsset {
  host_name: string;
  ip: string;
  score: number;
}

// Backwards-compatible alias for any consumer referencing PriorityAsset
export type PriorityAsset = PageRankAsset;

export interface RiskPrioritiesDeckProps {
  selectedAssetId?: string;
  onSelectAsset?: (assetId: string) => void;
  tenantId?: string;
  organizationName?: string;
}

export const RiskPrioritiesDeck: React.FC<RiskPrioritiesDeckProps> = ({
  selectedAssetId,
  onSelectAsset,
  tenantId,
  organizationName,
}) => {
  const [rankings, setRankings] = useState<PageRankAsset[] | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeHost, setActiveHost] = useState<string | null>(null);

  // Fetch PageRank rankings through authenticated API client for verified tenant
  const fetchRankings = useCallback(
    async (signal?: AbortSignal, silentRefresh: boolean = false) => {
      if (!tenantId) {
        setRankings(null);
        setActiveHost(null);
        setError(null);
        setLoading(false);
        return;
      }

      if (silentRefresh) {
        setIsRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);

      try {
        const res = await authenticatedFetch(
          `${API_BASE}/api/v1/threat/pagerank/${encodeURIComponent(tenantId)}`,
          { signal }
        );

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `HTTP ${res.status}: Failed to load PageRank`);
        }

        const data: PageRankAsset[] = await res.json();
        if (signal?.aborted) return;

        if (Array.isArray(data)) {
          setRankings(data);
          // Maintain active host selection if valid, or default to highest ranked asset
          if (data.length > 0) {
            setActiveHost((prev) => {
              const matchedSelected = selectedAssetId
                ? data.find((a) => a.host_name === selectedAssetId || a.ip === selectedAssetId)
                : null;
              if (matchedSelected) return matchedSelected.host_name;
              if (prev && data.some((a) => a.host_name === prev)) return prev;
              return data[0].host_name;
            });
          } else {
            setActiveHost(null);
          }
        } else {
          setRankings([]);
          setActiveHost(null);
        }
      } catch (err: unknown) {
        if (signal?.aborted) return;
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
        setRankings([]);
        setActiveHost(null);
      } finally {
        if (!signal?.aborted) {
          setLoading(false);
          setIsRefreshing(false);
        }
      }
    },
    [tenantId, selectedAssetId]
  );

  // Synchronize when tenantId changes: clear immediately to prevent cross-tenant state leakage
  useEffect(() => {
    setRankings(null);
    setActiveHost(null);
    setError(null);

    const controller = new AbortController();
    fetchRankings(controller.signal);

    return () => {
      controller.abort();
    };
  }, [tenantId, fetchRankings]);

  // Synchronize external asset selection if available
  useEffect(() => {
    if (selectedAssetId && rankings && rankings.length > 0) {
      const match = rankings.find(
        (a) => a.host_name === selectedAssetId || a.ip === selectedAssetId
      );
      if (match) {
        setActiveHost(match.host_name);
      }
    }
  }, [selectedAssetId, rankings]);

  const handleSelect = (asset: PageRankAsset) => {
    setActiveHost(asset.host_name);
    if (onSelectAsset) {
      onSelectAsset(asset.host_name);
    }
  };

  const handleManualRefresh = () => {
    fetchRankings(undefined, true);
  };

  const activeAsset =
    rankings && rankings.length > 0
      ? rankings.find((a) => a.host_name === activeHost) || rankings[0]
      : null;

  const activeRank =
    activeAsset && rankings ? rankings.indexOf(activeAsset) + 1 : 1;

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-4 sm:p-6 shadow-warm-sm space-y-5">
      {/* ── Section Header ────────────────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3 border-b border-[#EEE6DC] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#E6A548]" />
            <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
              Priority Infrastructure Assets
            </h3>
          </div>
          <p className="text-xs text-[#645C64] mt-0.5">
            Structural connectivity priorities queried live from active tenant topology. Identifies critical bridge and transit assets.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing || loading || !tenantId}
            className="px-2.5 py-1 rounded-md bg-[#FAF7F2] hover:bg-[#F5EFE6] border border-[#DFD6C9] text-[#645C64] hover:text-[#302B30] font-bold text-xs transition-colors disabled:opacity-50 cursor-pointer flex items-center gap-1.5"
            title="Refresh priorities from live FalkorDB graph"
          >
            <span className={isRefreshing ? "animate-spin" : ""}>↻</span>
            <span>{isRefreshing ? "Refreshing…" : "Refresh Priorities"}</span>
          </button>
          <span className="text-[#82465D] bg-[#FAF7F2] border border-[#DFD6C9] px-2.5 py-1 rounded-md font-bold text-[11px]">
            Live Tenant Topology
          </span>
        </div>
      </div>

      {/* ── State: Loading ────────────────────────────────────────────── */}
      {loading && rankings === null && (
        <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] space-y-3 font-mono">
          <div className="w-7 h-7 rounded-full border-2 border-[#D26A50] border-t-transparent animate-spin mx-auto" />
          <p className="text-xs text-[#645C64]">
            Evaluating structural priority rankings across active tenant topology…
          </p>
        </div>
      )}

      {/* ── State: Error ──────────────────────────────────────────────── */}
      {!loading && error && (
        <div className="flex flex-col items-center justify-center p-8 text-center rounded-xl bg-[#FAF7F2] border border-[#F3C4B8] space-y-3 font-mono">
          <div className="w-8 h-8 rounded-full bg-[#FBF0ED] flex items-center justify-center text-[#C24128] font-bold text-sm">
            ⚠
          </div>
          <div>
            <h4 className="text-xs font-bold text-[#C24128] uppercase">
              Failed to load priority rankings
            </h4>
            <p className="text-xs text-[#645C64] mt-1 max-w-md">{error}</p>
          </div>
          <button
            onClick={() => fetchRankings(undefined, false)}
            className="px-3 py-1.5 rounded-lg bg-[#FAF7F2] hover:bg-[#FFFFFF] border border-[#DFD6C9] text-xs font-bold text-[#302B30] shadow-warm-xs transition-colors cursor-pointer"
          >
            Retry Query
          </button>
        </div>
      )}

      {/* ── State: Empty ──────────────────────────────────────────────── */}
      {!loading && !error && rankings !== null && rankings.length === 0 && (
        <div className="flex flex-col items-center justify-center p-8 text-center rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] space-y-2 font-mono">
          <span className="text-base text-[#928992]">∅</span>
          <h4 className="text-xs font-bold text-[#302B30] uppercase">
            No Priority Infrastructure Data Available
          </h4>
          <p className="text-xs text-[#645C64] max-w-md">
            No active communication graph found. Ensure Host nodes and COMMUNICATES relationships exist for workspace{" "}
            <code className="text-[#82465D] font-bold">{organizationName || "active workspace"}</code>.
          </p>
        </div>
      )}

      {/* ── State: Analytical Asset Grid (Derived from Live PageRank) ───── */}
      {!loading && rankings && rankings.length > 0 && activeAsset && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Ranked Asset Selector Cards (5 Cols) */}
          <div className="lg:col-span-5 space-y-2">
            {rankings.map((asset, index) => {
              const rank = index + 1;
              const isSelected = activeHost === asset.host_name;
              return (
                <button
                  key={`${asset.host_name}-${index}`}
                  onClick={() => handleSelect(asset)}
                  className={`w-full text-left p-3 rounded-xl border transition-all flex items-center justify-between font-mono text-xs cursor-pointer ${
                    isSelected
                      ? "bg-[#FAF7F2] border-[#D26A50] shadow-warm-xs ring-1 ring-[#D26A50]"
                      : "bg-[#FFFFFF] border-[#DFD6C9] hover:border-[#82465D]/40 hover:bg-[#FAF7F2]/50"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`w-6 h-6 rounded-lg flex items-center justify-center font-bold text-[11px] ${
                        rank === 1
                          ? "bg-[#D26A50] text-white"
                          : rank === 2
                          ? "bg-[#E6A548] text-white"
                          : "bg-[#EEE6DC] text-[#302B30]"
                      }`}
                    >
                      #{rank}
                    </span>
                    <div>
                      <h4 className="font-bold text-[#302B30]">{asset.host_name}</h4>
                      <span className="text-[10px] text-[#645C64]">{asset.ip}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="block text-[11px] font-bold text-[#82465D]">
                      Priority #{rank}
                    </span>
                    <span className="text-[10px] text-[#928992]">
                      {rank === 1 ? "Top Hub" : rank <= 3 ? "Core Transit" : "Connected"}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Selected Asset Detailed Analytical Dossier (7 Cols) */}
          <div className="lg:col-span-7 bg-[#FAF7F2] border border-[#DFD6C9] rounded-xl p-5 space-y-4 font-mono text-xs">
            <div className="flex justify-between items-center border-b border-[#EEE6DC] pb-3">
              <div>
                <span className="text-[10px] text-[#928992] uppercase block">
                  Priority #{activeRank} Infrastructure Asset
                </span>
                <h4 className="text-base font-extrabold text-[#302B30]">{activeAsset.host_name}</h4>
                <span className="text-[11px] text-[#645C64]">{activeAsset.ip}</span>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-[#928992] block uppercase">Network Role</span>
                <strong className="text-xs font-bold text-[#82465D]">
                  {activeRank === 1
                    ? "Primary Connectivity Hub"
                    : activeRank <= 3
                    ? "Core Transit / Gateway Node"
                    : "Lateral Path Relay Node"}
                </strong>
              </div>
            </div>

            {/* Analyst Context & Supporting Evidence */}
            <div className="space-y-1.5">
              <span className="text-[10px] text-[#928992] uppercase block">Analyst Supporting Evidence</span>
              <p className="text-[#302B30] leading-relaxed bg-[#FFFFFF] p-3 rounded-lg border border-[#EEE6DC]">
                Ranked #{activeRank} of {rankings.length} monitored assets by structural connectivity in{" "}
                <span className="text-[#82465D] font-bold">{organizationName || "active workspace"}</span>. This host occupies a dense crossroad in the communication graph; compromise here increases potential lateral reach to other internal segments.
              </p>
            </div>

            {/* Context Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
                <span className="text-[10px] text-[#928992] uppercase block">Topological Position</span>
                <strong className="text-[#302B30] block">
                  {activeRank === 1
                    ? "High-Degree Convergence"
                    : activeRank <= 3
                    ? "Gateway Interconnect"
                    : "Secondary Internal Relay"}
                </strong>
                <span className="text-[10px] text-[#645C64] block">
                  Derived from live COMMUNICATES edges
                </span>
              </div>

              <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
                <span className="text-[10px] text-[#928992] uppercase block">Recommended Analyst Action</span>
                <strong className="text-[#302B30] block">
                  {activeRank <= 2
                    ? "Inspect Perimeter & Bridges"
                    : "Verify Ingress & Egress Rules"}
                </strong>
                <span className="text-[10px] text-[#26694E] block">
                  Evaluate exposure in workspace
                </span>
              </div>
            </div>

            {/* Navigation / Inspection Action Button */}
            <div className="pt-1 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => handleSelect(activeAsset)}
                className="px-4 py-2 rounded-xl bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-xs shadow-warm-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>⚡</span>
                <span>Select &amp; Inspect in Investigation Workspace</span>
              </button>
            </div>

            {/* Advanced Centrality Metrics Disclosure */}
            <details className="border-t border-[#EEE6DC] pt-2 text-[11px]">
              <summary className="cursor-pointer text-[#82465D] hover:underline font-bold py-1 select-none flex items-center justify-between">
                <span>Advanced Centrality Metrics &amp; Algorithm Details</span>
                <span className="text-[10px] text-[#928992]">Show Details ▾</span>
              </summary>
              <div className="mt-2 p-3 rounded-lg bg-[#FFFFFF] border border-[#EEE6DC] space-y-2 text-[#645C64]">
                <div className="flex justify-between">
                  <span>Graph Engine:</span>
                  <strong className="text-[#302B30]">FalkorDB GraphBLAS algo.pageRank</strong>
                </div>
                <div className="flex justify-between">
                  <span>Raw Centrality Score:</span>
                  <strong className="text-[#82465D] font-mono">{activeAsset.score.toFixed(6)}</strong>
                </div>
                <div className="flex justify-between">
                  <span>Relative Position:</span>
                  <strong className="text-[#302B30]">Rank #{activeRank} of {rankings.length}</strong>
                </div>
                <p className="text-[10px] text-[#928992] pt-1 border-t border-[#EEE6DC] leading-normal italic">
                  Note: PageRank centrality indicates structural graph importance across network connections; it is not a vulnerability classification or severity score.
                </p>
              </div>
            </details>
          </div>
        </div>
      )}
    </div>
  );
};
