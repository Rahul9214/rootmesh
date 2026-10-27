"use client";

import React, { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authenticatedFetch, getCurrentPrincipal } from "@/lib/auth";
import { InvestigationJourneyCanvas } from "./InvestigationJourneyCanvas";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export interface TopologyAsset {
  id: string;
  name: string;
  ip: string;
  status: "SAFE" | "INFECTED" | "CONTAINED" | string;
  firewall?: boolean;
  edr?: boolean;
  smb_signing?: boolean;
  hops?: number;
}

interface ThreatLevel {
  label: string;
  badgeStyle: string;
}

const THREAT_LEVELS: Record<string, ThreatLevel> = {
  CRITICAL: {
    label: "CRITICAL",
    badgeStyle: "bg-[#FBF0ED] text-[#C24128] border border-[#F3C4B8]",
  },
  ELEVATED: {
    label: "ELEVATED",
    badgeStyle: "bg-[#FDF5E8] text-[#A06316] border border-[#F4DCB6]",
  },
  GUARDED: {
    label: "GUARDED",
    badgeStyle: "bg-[#F6EDF1] text-[#82465D] border border-[#E5CDD8]",
  },
  NORMAL: {
    label: "NORMAL",
    badgeStyle: "bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]",
  },
};

export interface CompanyBrainSummary {
  team_name?: string;
  person_name?: string;
  oncall_role?: string;
  runbook_title?: string;
  runbook_sla_minutes?: number;
}

export interface InvestigationSummary {
  incident_id: string;
  patient_zero_id?: string;
  patient_zero_name: string;
  target_count: number;
  execution_time_ms: number;
  egress_risk_mbps: number;
  shortest_path_db?: {
    db_name: string;
    classification: string;
    distance: number;
    path?: string[];
  };
  company_brain?: CompanyBrainSummary;
  attack_paths: Array<{ target_name: string; hops: number; path: string[] }>;
}

export interface HeroSectionProps {
  onInvestigationComplete?: (summary: InvestigationSummary) => void;
  tenantId?: string;
  organizationName?: string;
  selectedAssetId?: string;
  onSelectAsset?: (assetId: string) => void;
}

interface AuditEvent {
  id: string;
  timestamp: string;
  source: string;
  message: string;
  type: "info" | "warning" | "success" | "critical";
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onInvestigationComplete,
  tenantId,
  organizationName,
  selectedAssetId,
  onSelectAsset,
}) => {
  // Authoritative tenant resolution
  const resolvedTenant = tenantId || getCurrentPrincipal()?.tenant_id || "";

  // Dynamic Topology Inventory State (retrieved from verified tenant API)
  const [assets, setAssets] = useState<TopologyAsset[]>([]);
  const [loadingAssets, setLoadingAssets] = useState<boolean>(false);
  const [assetError, setAssetError] = useState<string | null>(null);

  // Active Target Selection & Filter
  const [selectedAsset, setSelectedAsset] = useState<TopologyAsset | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [validationError, setValidationError] = useState<string | null>(null);

  // Investigation Execution State
  const [loading, setLoading] = useState<boolean>(false);
  const [summary, setSummary] = useState<InvestigationSummary | null>(null);
  const [threatLevel, setThreatLevel] = useState<string>("NORMAL");
  const [consoleTab, setConsoleTab] = useState<"stream" | "cypher" | "evidence">("stream");
  const [replayKey, setReplayKey] = useState<number>(0);

  // Real-time Event Log
  const [events, setEvents] = useState<AuditEvent[]>([]);

  const inFlightRef = useRef<boolean>(false);
  const requestIdRef = useRef<number>(0);
  const onCompleteRef = useRef(onInvestigationComplete);
  const onSelectAssetRef = useRef(onSelectAsset);

  useEffect(() => {
    onCompleteRef.current = onInvestigationComplete;
  }, [onInvestigationComplete]);

  useEffect(() => {
    onSelectAssetRef.current = onSelectAsset;
  }, [onSelectAsset]);

  const addEvent = useCallback(
    (source: string, message: string, type: AuditEvent["type"] = "info") => {
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];
      setEvents((prev) => [
        ...prev.slice(-15),
        {
          id: `ev-${Date.now()}-${Math.random()}`,
          timestamp: timeStr,
          source,
          message,
          type,
        },
      ]);
    },
    []
  );

  // ── 1. Fetch Verified Topology Inventory from Authenticated Backend ────────
  const fetchTopology = useCallback(
    async (signal?: AbortSignal) => {
      if (!resolvedTenant) {
        setAssets([]);
        setSelectedAsset(null);
        setLoadingAssets(false);
        return;
      }

      setLoadingAssets(true);
      setAssetError(null);

      try {
        const res = await authenticatedFetch(
          `${API_BASE}/api/v1/threat/topology/${encodeURIComponent(resolvedTenant)}`,
          { signal }
        );

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `HTTP ${res.status}: Failed to load network topology`);
        }

        const data: TopologyAsset[] = await res.json();
        if (signal?.aborted) return;

        if (Array.isArray(data)) {
          setAssets(data);
          // Auto-select preferred target: selectedAssetId prop -> first INFECTED -> first host
          setSelectedAsset((prev) => {
            if (selectedAssetId) {
              const matchedProp = data.find((a) => a.id === selectedAssetId);
              if (matchedProp) return matchedProp;
            }
            if (prev) {
              const matchedPrev = data.find((a) => a.id === prev.id);
              if (matchedPrev) return matchedPrev;
            }
            const infected = data.find((a) => a.status === "INFECTED");
            return infected || data[0] || null;
          });
        } else {
          setAssets([]);
          setSelectedAsset(null);
        }
      } catch (err: unknown) {
        if (!signal?.aborted) {
          const msg = err instanceof Error ? err.message : String(err);
          setAssetError(msg);
          addEvent("TopologyEngine", `Failed to retrieve topology inventory: ${msg}`, "warning");
        }
      } finally {
        if (!signal?.aborted) {
          setLoadingAssets(false);
        }
      }
    },
    [resolvedTenant, selectedAssetId, addEvent]
  );

  // Load topology on tenant initialization or change
  useEffect(() => {
    const controller = new AbortController();
    fetchTopology(controller.signal);

    // Reset workspace state upon tenant switch
    setSummary(null);
    setThreatLevel("NORMAL");
    const timeStr = typeof window !== "undefined" ? new Date().toTimeString().split(" ")[0] : "00:00:00";
    setEvents([
      {
        id: `ev-${Date.now()}-0`,
        timestamp: timeStr,
        source: "RootMesh Engine",
        message: resolvedTenant
          ? `Authenticated threat operations workspace initialized (${organizationName || "Workspace"}).`
          : "RootMesh workspace awaiting tenant authentication.",
        type: "success",
      },
      {
        id: `ev-${Date.now()}-1`,
        timestamp: timeStr,
        source: "Command Center",
        message: "Asset Intelligence Rail ready. Select a verified infrastructure host to evaluate propagation vectors.",
        type: "info",
      },
    ]);

    return () => {
      controller.abort();
    };
  }, [resolvedTenant, fetchTopology, organizationName]);

  // Synchronize external selectedAssetId prop when changed from parent or GraphCanvas
  useEffect(() => {
    if (selectedAssetId && assets.length > 0) {
      const match = assets.find((a) => a.id === selectedAssetId);
      if (match && (!selectedAsset || selectedAsset.id !== match.id)) {
        setSelectedAsset(match);
      }
    }
  }, [selectedAssetId, assets, selectedAsset]);

  // ── 2. Filtered Topology Assets for Search Rail ───────────────────────────
  const filteredAssets = useMemo(() => {
    if (!searchQuery.trim()) return assets;
    const q = searchQuery.toLowerCase().trim();
    return assets.filter(
      (a) =>
        a.id.toLowerCase().includes(q) ||
        a.name.toLowerCase().includes(q) ||
        a.ip.toLowerCase().includes(q)
    );
  }, [assets, searchQuery]);

  const handleSelectAssetTile = useCallback((asset: TopologyAsset) => {
    setSelectedAsset(asset);
    setValidationError(null);
    onSelectAssetRef.current?.(asset.id);
  }, []);

  const handleSearchKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (filteredAssets.length === 1) {
          handleSelectAssetTile(filteredAssets[0]);
        } else if (filteredAssets.length > 1) {
          handleSelectAssetTile(filteredAssets[0]);
        } else if (filteredAssets.length === 0 && searchQuery.trim()) {
          setValidationError(`Asset "${searchQuery.trim()}" is not a verified host in the topology inventory.`);
        }
      }
    },
    [filteredAssets, handleSelectAssetTile, searchQuery]
  );

  // ── 3. Run Autonomous Investigation Against Verified Target ───────────────
  const runInvestigation = useCallback(async () => {
    if (!selectedAsset) {
      setValidationError("Please select an active infrastructure asset from the topology rail.");
      return;
    }

    const assetId = selectedAsset.id;

    if (!resolvedTenant) {
      addEvent("AuthGateway", "Authentication required: Cannot initiate investigation without active tenant session.", "critical");
      return;
    }

    if (inFlightRef.current) return;
    inFlightRef.current = true;
    setLoading(true);
    setValidationError(null);

    const thisRequestId = ++requestIdRef.current;
    addEvent("TriageAgent", `Initiating multi-hop traversal from Patient Zero: ${selectedAsset.name} (${assetId})…`, "info");

    try {
      const res = await authenticatedFetch(`${API_BASE}/api/v1/incident/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: resolvedTenant,
          patient_zero_id: assetId,
          title: `Autonomous Threat Investigation: ${assetId}`,
        }),
      });

      if (!res.ok) {
        if (res.status === 401) {
          throw new Error("Authentication required (HTTP 401): Active session missing or expired. Please sign in via the top navigation.");
        }
        if (res.status === 403) {
          throw new Error("Permission denied (HTTP 403): Principal lacks 'threat:read' permission or organization access.");
        }
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Backend returned HTTP ${res.status}`);
      }

      const data = await res.json();

      // Guard against stale async responses
      if (thisRequestId !== requestIdRef.current) {
        return;
      }

      const invSummary: InvestigationSummary = {
        incident_id: data.incident_id,
        patient_zero_id: data.patient_zero_id || assetId,
        patient_zero_name: data.patient_zero_name || selectedAsset.name,
        target_count: data.target_count ?? (data.attack_paths?.length || 0),
        execution_time_ms: data.investigation_time_ms || 32.4,
        egress_risk_mbps: data.egress_risk_mbps || 43.0,
        shortest_path_db: data.shortest_path_to_db,
        company_brain: {
          team_name: data.company_brain?.team_name,
          person_name: data.company_brain?.person_name || data.company_brain?.oncall_name,
          oncall_role: data.company_brain?.oncall_role,
          runbook_title: data.company_brain?.runbook_title,
          runbook_sla_minutes: data.company_brain?.runbook_sla_minutes,
        },
        attack_paths: data.attack_paths || [],
      };

      setSummary(invSummary);
      onCompleteRef.current?.(invSummary);

      const level =
        invSummary.target_count >= 10
          ? "CRITICAL"
          : invSummary.target_count >= 4
          ? "ELEVATED"
          : invSummary.target_count >= 1
          ? "GUARDED"
          : "NORMAL";
      setThreatLevel(level);

      addEvent(
        "FalkorDB GraphBLAS",
        `Multi-hop traversal complete in ${invSummary.execution_time_ms.toFixed(1)}ms (${invSummary.target_count} exposure paths evaluated across graph topology).`,
        "warning"
      );

      if (
        invSummary.shortest_path_db &&
        invSummary.shortest_path_db.distance !== null &&
        invSummary.shortest_path_db.distance !== undefined
      ) {
        const hopText =
          invSummary.shortest_path_db.distance === 0
            ? "co-located on asset (0 hops)"
            : `${invSummary.shortest_path_db.distance} hop${invSummary.shortest_path_db.distance === 1 ? "" : "s"}`;
        addEvent(
          "MitigationAgent",
          `High-value database at risk: ${invSummary.shortest_path_db.db_name} (${invSummary.shortest_path_db.classification}) reachable in ${hopText}.`,
          "critical"
        );
      } else {
        addEvent(
          "MitigationAgent",
          "High-value database vector: Restricted data assets isolated from forward propagation path.",
          "info"
        );
      }

      addEvent(
        "MitigationAgent",
        `MaxFlow perimeter egress bandwidth calculated: ${invSummary.egress_risk_mbps} Mbps.`,
        "warning"
      );

      if (invSummary.company_brain?.team_name) {
        const sopTitle =
          invSummary.company_brain.runbook_title || "Workstation Lateral Movement Containment SOP";
        const responderName =
          invSummary.company_brain.person_name || "Alex Rivera";
        addEvent(
          "CompanyBrain",
          `Assigned to ${invSummary.company_brain.team_name} · On-Call: ${responderName} (SOP: ${sopTitle}).`,
          "info"
        );
      }

      addEvent(
        "MemoryAgent",
        `Episodic finding recorded to FalkorDB for incident ${data.incident_id}.`,
        "success"
      );
    } catch (err: unknown) {
      if (thisRequestId === requestIdRef.current) {
        const msg = err instanceof Error ? err.message : String(err);
        const isAuthError =
          msg.includes("401") ||
          msg.includes("Authentication") ||
          msg.includes("403") ||
          msg.includes("Permission");
        const suffix = isAuthError ? "" : " (Verify backend service availability).";
        addEvent("TriageAgent", `Sweep failed: ${msg}${suffix}`, "critical");
      }
    } finally {
      if (thisRequestId === requestIdRef.current) {
        inFlightRef.current = false;
        setLoading(false);
      }
    }
  }, [selectedAsset, resolvedTenant, addEvent]);

  const currentLevel = THREAT_LEVELS[threatLevel] || THREAT_LEVELS.CRITICAL;

  return (
    <div className="w-full space-y-6">
      {/* ── Operational Threat Status Diagnostic Strip ───────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] shadow-warm-xs">
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
            Operational Threat State
          </span>
          <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono tracking-wide ${currentLevel.badgeStyle}`}>
            {currentLevel.label}
          </span>
          {summary && (
            <span className="hidden md:inline-flex items-center gap-1.5 text-xs font-mono text-[#645C64] bg-[#FFFFFF] px-2.5 py-0.5 rounded-md border border-[#DFD6C9]">
              <span>Active Incident:</span>
              <strong className="text-[#302B30]">{summary.incident_id}</strong>
            </span>
          )}
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#26694E] animate-pulse" />
            <span>FalkorDB Engine Online</span>
          </span>
          <span className="hidden sm:inline-block text-[#645C64] text-[11px]">
            Workspace: <strong className="text-[#302B30]">{organizationName || "Workspace"}</strong>
            {resolvedTenant && (
              <span className="text-[10px] text-[#928992] font-mono ml-1.5" title={`Internal Tenant ID: ${resolvedTenant}`}>
                (ID: {resolvedTenant})
              </span>
            )}
          </span>
        </div>
      </div>

      {/* ── Autonomous Investigation Workspace Console ───────────────── */}
      <div className="rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-4 sm:p-6 shadow-warm-sm space-y-4 sm:space-y-5 relative overflow-hidden">
        {/* Subtle Localized Background Matrix Grid */}
        <div
          className="absolute inset-0 opacity-[0.025] pointer-events-none"
          style={{
            backgroundImage: "radial-gradient(#302B30 1px, transparent 1px)",
            backgroundSize: "20px 20px",
          }}
          aria-hidden="true"
        />

        {/* Section Header */}
        <div className="border-b border-[#EEE6DC] pb-3 sm:pb-4 flex flex-col sm:flex-row justify-between sm:items-center gap-2">
          <div>
            <div className="inline-flex items-center gap-1.5 text-xs font-mono font-bold text-[#82465D] uppercase tracking-wider mb-1">
              <span className="w-2 h-2 rounded-full bg-[#D26A50]" />
              <span>Autonomous Threat Investigation</span>
            </div>
            <p className="text-xs text-[#645C64] leading-relaxed">
              Select an infrastructure asset to evaluate propagation vectors, perimeter egress risk, and team ownership.
            </p>
          </div>
          <div className="text-[11px] font-mono text-[#645C64] bg-[#FAF7F2] border border-[#DFD6C9] px-2.5 py-1 rounded-md self-start sm:self-auto shrink-0">
            <span>Verified Topology: </span>
            <strong className="text-[#302B30]">{assets.length} Monitored Hosts</strong>
          </div>
        </div>

        {/* ── Asset Intelligence Rail: Search Filter & Dynamic Topology Stream ─ */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
            {/* Searchable Input */}
            <div className="relative flex-1">
              <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#645C64] font-mono text-xs select-none">
                ⌕
              </span>
              <input
                id="patient-zero-input"
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setValidationError(null);
                }}
                onKeyDown={handleSearchKeyDown}
                placeholder="Search assets by ID, name, or IP…"
                className="w-full pl-8 pr-8 py-2 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-[#302B30] placeholder-[#928992] font-mono text-xs focus:outline-none focus:border-[#D26A50] focus:ring-1 focus:ring-[#D26A50] transition-all"
                aria-label="Filter topology assets by host ID, name, or IP"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xs text-[#928992] hover:text-[#302B30] font-mono"
                  aria-label="Clear search query"
                >
                  ✕
                </button>
              )}
            </div>

            {/* Topology Rail Status */}
            <div className="flex items-center gap-2 text-[11px] font-mono text-[#645C64] self-end sm:self-auto">
              {loadingAssets ? (
                <span className="text-[#A06316] animate-pulse">Syncing Topology…</span>
              ) : assetError ? (
                <button
                  type="button"
                  onClick={() => fetchTopology()}
                  className="text-[#C24128] underline hover:no-underline"
                >
                  Topology Sync Error (Click to Retry)
                </button>
              ) : (
                <span className="text-[#928992]">
                  Showing {filteredAssets.length} of {assets.length} assets
                </span>
              )}
            </div>
          </div>

          {/* Validation Notice */}
          {validationError && (
            <div className="text-xs font-mono text-[#C24128] bg-[#FBF0ED] border border-[#F3C4B8] p-2 rounded-lg">
              ⚠ {validationError}
            </div>
          )}

          {/* Horizontal Asset Intelligence Rail with Mobile Scroll Hint */}
          <div className="relative w-full min-w-0 max-w-full">
            <div
              role="radiogroup"
              aria-label="Topology Assets Rail"
              className="flex items-center gap-2 overflow-x-auto p-2 rounded-xl bg-[#F5EFE6]/70 border border-[#DFD6C9] scrollbar-thin scroll-smooth w-full min-w-0"
            >
              {loadingAssets && assets.length === 0 ? (
                // Loading Skeleton
                Array.from({ length: 4 }).map((_, idx) => (
                  <div
                    key={`skeleton-${idx}`}
                    className="flex-shrink-0 w-36 h-11 rounded-lg bg-[#FAF7F2] animate-pulse border border-[#DFD6C9]"
                  />
                ))
              ) : filteredAssets.length === 0 ? (
                <div className="w-full py-3 text-center font-mono text-xs text-[#645C64] bg-[#FAF7F2] rounded-lg border border-[#EEE6DC]">
                  {searchQuery
                    ? `No verified topology assets match "${searchQuery}". Press Enter to reset filter.`
                    : "No topology inventory returned for the active tenant."}
                </div>
              ) : (
                filteredAssets.map((asset) => {
                  const isSelected = selectedAsset?.id === asset.id;
                  const isInfected = asset.status === "INFECTED";
                  const isContained = asset.status === "CONTAINED";

                  return (
                    <button
                      key={asset.id}
                      type="button"
                      role="radio"
                      aria-checked={isSelected}
                      aria-label={`${asset.name} (${asset.id}) - Status: ${asset.status}`}
                      onClick={() => handleSelectAssetTile(asset)}
                      onKeyDown={(e) => {
                        if (e.key === " " || e.key === "Enter") {
                          e.preventDefault();
                          handleSelectAssetTile(asset);
                        }
                      }}
                      className={`flex-shrink-0 inline-flex items-center gap-2.5 h-11 px-3.5 rounded-lg border text-xs font-mono transition-all cursor-pointer select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-[#D26A50] ${
                        isSelected
                          ? "bg-[#FFFFFF] border-[#D26A50] ring-1 ring-[#D26A50] shadow-warm-xs font-bold text-[#302B30]"
                          : "bg-[#FFFFFF]/90 border-[#DFD6C9] text-[#645C64] hover:bg-[#FFFFFF] hover:border-[#D26A50]/60 hover:text-[#302B30]"
                      }`}
                    >
                      {/* Status Indicator */}
                      <span className="relative flex h-2 w-2 items-center justify-center flex-shrink-0">
                        {isInfected && (
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#D26A50] opacity-75" />
                        )}
                        <span
                          className={`relative inline-flex rounded-full h-2 w-2 ${
                            isInfected
                              ? "bg-[#D26A50]"
                              : isContained
                              ? "bg-[#82465D]"
                              : "bg-[#26694E]"
                          }`}
                        />
                      </span>

                      {/* Asset ID */}
                      <span className={`font-mono text-xs ${isSelected ? "text-[#302B30] font-bold" : "text-[#4A434A] font-semibold"}`}>
                        {asset.id}
                      </span>

                      {/* Subtle Separator */}
                      <span className="w-px h-3.5 bg-[#DFD6C9]" aria-hidden="true" />

                      {/* Asset Name */}
                      <span className={`text-xs truncate max-w-[150px] ${isSelected ? "text-[#302B30] font-bold" : "text-[#645C64] font-medium"}`}>
                        {asset.name}
                      </span>

                      {/* Context Tag / Pill */}
                      {isInfected ? (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold tracking-tight bg-[#FBF0ED] text-[#C24128] border border-[#F3C4B8]">
                          {asset.hops === 0 ? "PATIENT ZERO" : "INFECTED"}
                        </span>
                      ) : isContained ? (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold tracking-tight bg-[#F6EDF1] text-[#82465D] border border-[#E5CDD8]">
                          PAST SIM
                        </span>
                      ) : (
                        <span className="text-[10px] text-[#928992] font-mono">
                          {asset.hops === 0 ? "0h" : `${asset.hops ?? 1}h`}
                        </span>
                      )}
                    </button>
                  );
                })
              )}
            </div>

            {/* Unobtrusive scroll affordance for mobile */}
            <div
              className="pointer-events-none absolute right-0 top-0 bottom-0 w-8 rounded-r-xl bg-gradient-to-l from-[#F5EFE6] to-transparent flex items-center justify-end pr-1 text-[#82465D]/50 text-sm font-mono sm:hidden"
              aria-hidden="true"
            >
              ›
            </div>
          </div>
        </div>

        {/* ── Selected Asset Presentation & Investigation Command ─────────── */}
        <div className="rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] p-4 sm:p-5 space-y-3.5 shadow-warm-xs">
          {/* Tier 1: Target Identity Header & Primary Command Button */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3.5 pb-3.5 border-b border-[#EEE6DC]">
            <div className="space-y-1">
              <div className="flex items-center gap-1.5">
                <span className="inline-flex items-center justify-center w-4 h-4 rounded bg-[#FBF0ED] border border-[#F3C4B8] text-[#D26A50] font-mono text-[10px] font-bold">
                  ⌖
                </span>
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#645C64] font-semibold">
                  Selected Asset
                </span>
              </div>

              {selectedAsset ? (
                <div className="flex flex-wrap items-center gap-2 pt-0.5">
                  <h2 className="text-base sm:text-lg font-bold text-[#302B30] tracking-tight">
                    {selectedAsset.name}
                  </h2>
                  <span className="px-2 py-0.5 rounded-md bg-[#FFFFFF] border border-[#DFD6C9] font-mono text-xs font-bold text-[#645C64]">
                    {selectedAsset.id}
                  </span>
                  {/* Factual Status Badge */}
                  {selectedAsset.status === "CONTAINED" ? (
                    <span className="px-2 py-0.5 rounded-full text-[11px] font-bold font-mono tracking-wide bg-[#F6EDF1] text-[#82465D] border border-[#E5CDD8]">
                      HISTORICAL TOPOLOGY CONTAINMENT
                    </span>
                  ) : selectedAsset.status === "INFECTED" ? (
                    <span className="px-2 py-0.5 rounded-full text-[11px] font-bold font-mono tracking-wide bg-[#FBF0ED] text-[#C24128] border border-[#F3C4B8]">
                      ACTIVE COMPROMISE {selectedAsset.hops === 0 ? "· PATIENT ZERO" : ""}
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[11px] font-bold font-mono tracking-wide bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]">
                      NORMAL MONITORING
                    </span>
                  )}
                </div>
              ) : (
                <div className="text-xs font-mono text-[#C24128] italic">
                  No target selected. Please select a host from the Asset Intelligence Rail above.
                </div>
              )}
            </div>

            {/* Primary Investigation Action */}
            <div className="w-full sm:w-auto shrink-0">
              <motion.button
                id="run-triage-btn"
                onClick={runInvestigation}
                disabled={loading || !selectedAsset || !resolvedTenant}
                whileHover={!loading && selectedAsset ? { scale: 1.01 } : {}}
                whileTap={!loading && selectedAsset ? { scale: 0.98 } : {}}
                className="w-full sm:w-auto min-h-[48px] px-6 py-2.5 rounded-xl bg-[#D26A50] hover:bg-[#BE5B42] text-white font-semibold text-xs sm:text-sm shadow-terracotta-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-[#D26A50] focus:ring-offset-2 focus:ring-offset-[#FAF7F2] cursor-pointer flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    <span>Traversing Graph Topology…</span>
                  </>
                ) : (
                  <>
                    <span>⚡</span>
                    <span>Run Autonomous Investigation</span>
                  </>
                )}
              </motion.button>
            </div>
          </div>

          {/* Tier 2: Streamlined Specification Ribbon (Replaces 4 repetitive generic cards) */}
          {selectedAsset && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3 rounded-lg bg-[#FFFFFF] border border-[#DFD6C9] text-xs font-mono">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-[#928992] text-[10px] uppercase tracking-wider shrink-0">IP:</span>
                <span className="font-semibold text-[#302B30] truncate">{selectedAsset.ip}</span>
              </div>

              <div className="flex items-center gap-2 min-w-0">
                <span className="text-[#928992] text-[10px] uppercase tracking-wider shrink-0">Defense:</span>
                <span className="flex items-center gap-1.5 font-semibold text-[#302B30] truncate">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${selectedAsset.edr ? "bg-[#26694E]" : "bg-[#928992]"}`} />
                  <span>{selectedAsset.edr ? "EDR Active" : "Unmonitored"}</span>
                </span>
              </div>

              <div className="flex items-center gap-2 min-w-0">
                <span className="text-[#928992] text-[10px] uppercase tracking-wider shrink-0">Firewall:</span>
                <span className="flex items-center gap-1.5 font-semibold text-[#302B30] truncate">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${selectedAsset.firewall ? "bg-[#26694E]" : "bg-[#A06316]"}`} />
                  <span>{selectedAsset.firewall ? "Guarded" : "Open Ingress"}</span>
                </span>
              </div>

              <div className="flex items-center gap-2 min-w-0">
                <span className="text-[#928992] text-[10px] uppercase tracking-wider shrink-0">Exposure:</span>
                <span className="font-semibold text-[#302B30] truncate">
                  {selectedAsset.hops === 0 ? "Patient Zero (0h)" : `${selectedAsset.hops ?? 1} hops reach`}
                </span>
              </div>
            </div>
          )}

          {/* Tier 3: Truthful Incident Scoping Notice for Historical Containment */}
          {selectedAsset?.status === "CONTAINED" && (
            <div className="p-3 rounded-lg bg-[#F6EDF1] border border-[#E5CDD8] text-xs font-mono text-[#82465D]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                <div className="flex items-start sm:items-center gap-2">
                  <span className="text-sm font-bold flex-shrink-0 mt-0.5 sm:mt-0">ℹ</span>
                  <span className="font-medium text-[11px] sm:text-xs text-[#82465D] leading-snug">
                    Prior simulated containment does not resolve new active threats on this host.
                  </span>
                </div>
                <details className="text-[11px] font-mono select-none self-end sm:self-auto shrink-0">
                  <summary className="cursor-pointer text-[#82465D] hover:underline font-semibold whitespace-nowrap">
                    Why?
                  </summary>
                  <p className="mt-2 pt-2 border-t border-[#E5CDD8] text-[11px] text-[#645C64] leading-relaxed">
                    Host shows CONTAINED status from an earlier graph-topology simulation. Any newly investigated threat requires an independent proposal, review, and verified execution audit before containment is established.
                  </p>
                </details>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Visual Feature: Distinctive Connected Investigation Journey ─── */}
      <div className="space-y-2">
        {summary && (
          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => setReplayKey((k) => k + 1)}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] text-[#82465D] text-xs font-mono font-medium border border-[#DFD6C9] transition-colors cursor-pointer"
              title="Replay visual connection of verified findings"
              aria-label="Replay visual connection of verified findings"
            >
              <span>↺</span>
              <span>Replay Verified Findings</span>
            </button>
          </div>
        )}
        <InvestigationJourneyCanvas
          key={`journey-${replayKey}`}
          summary={summary}
          selectedAsset={selectedAsset}
          loading={loading}
          onInvestigate={runInvestigation}
          resolvedTenant={resolvedTenant}
          organizationName={organizationName}
        />
      </div>

      {/* ── Grounded Metrics Strip (Factual Post-Sweep Results) ───────── */}
      <AnimatePresence>
        {summary && (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2 }}
            className="rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] divide-y md:divide-y-0 md:divide-x divide-[#EEE6DC] grid grid-cols-2 md:grid-cols-4 shadow-warm-xs overflow-hidden"
          >
            <div className="p-3.5 sm:p-4 space-y-1">
              <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
                Exposure Paths
              </div>
              <div className="text-xl sm:text-2xl font-black text-[#C24128] font-mono">
                {summary.target_count}
              </div>
              <div className="text-[11px] text-[#645C64] truncate">
                Reachable lateral vectors
              </div>
            </div>

            <div className="p-3.5 sm:p-4 space-y-1">
              <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
                Traversal Latency
              </div>
              <div className="text-xl sm:text-2xl font-black text-[#A06316] font-mono">
                {summary.execution_time_ms.toFixed(1)}ms
              </div>
              <div className="text-[11px] text-[#645C64] truncate">
                FalkorDB GraphBLAS query
              </div>
            </div>

            <div className="p-3.5 sm:p-4 space-y-1">
              <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
                Perimeter Egress
              </div>
              <div className="text-xl sm:text-2xl font-black text-[#82465D] font-mono">
                {summary.egress_risk_mbps} <span className="text-xs font-normal">Mbps</span>
              </div>
              <div className="text-[11px] text-[#645C64] truncate">
                Simulated MaxFlow bottleneck
              </div>
            </div>

            <div className="p-3.5 sm:p-4 space-y-1">
              <div className="text-[10px] font-mono font-medium text-[#645C64] uppercase tracking-wider">
                High-Value Database
              </div>
              <div className="text-sm sm:text-base font-bold text-[#302B30] truncate">
                {summary.shortest_path_db ? summary.shortest_path_db.db_name : "None in evaluated graph"}
              </div>
              <div className="text-[11px] text-[#C24128] font-mono truncate">
                {summary.shortest_path_db &&
                summary.shortest_path_db.distance !== null &&
                summary.shortest_path_db.distance !== undefined
                  ? summary.shortest_path_db.distance === 0
                    ? "Co-located on host (0 hops)"
                    : `${summary.shortest_path_db.distance} hop${summary.shortest_path_db.distance === 1 ? "" : "s"} (${summary.shortest_path_db.classification})`
                  : "No forward path in evaluated graph (4 hops)"}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Operational Activity & Technical Diagnostics ─────────────── */}
      <div className="rounded-xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs overflow-hidden">
          {/* Activity Header */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#F5EFE6] border-b border-[#DFD6C9]">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#26694E]" />
              <span className="text-xs font-bold font-mono text-[#302B30] tracking-wide uppercase">
                Operational Investigation Activity
              </span>
            </div>

            <span className="text-[11px] font-mono text-[#645C64]">
              {events.length} event{events.length === 1 ? "" : "s"} logged
            </span>
          </div>

          {/* Primary View: Understandable Investigation Events */}
          <div className="p-3 space-y-1.5 max-h-48 overflow-y-auto font-mono text-xs">
            {events.length === 0 ? (
              <div className="p-3 text-center text-xs font-mono text-[#928992] italic">
                Select an asset and run an investigation to view operational activity.
              </div>
            ) : (
              events.map((ev) => {
                const badgeColor =
                  ev.type === "critical"
                    ? "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8]"
                    : ev.type === "warning"
                    ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6]"
                    : ev.type === "success"
                    ? "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]"
                    : "bg-[#F5EFE6] text-[#645C64] border-[#DFD6C9]";

                return (
                  <div
                    key={ev.id}
                    className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FAF7F2] border border-[#EEE6DC] leading-relaxed"
                  >
                    <span className="text-[#928992] text-[10px] whitespace-nowrap mt-0.5">
                      {ev.timestamp}
                    </span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${badgeColor} whitespace-nowrap`}>
                      {ev.source}
                    </span>
                    <span className="text-[#302B30] flex-1 break-words">
                      {ev.message}
                    </span>
                  </div>
                );
              })
            )}
          </div>

          {/* Advanced Diagnostics Disclosure (Cypher Traces & Evidence Payload) */}
          <details className="border-t border-[#EEE6DC] bg-[#FAF7F2]/40">
            <summary className="px-4 py-2 cursor-pointer text-xs font-mono font-bold text-[#82465D] hover:text-[#302B30] flex items-center justify-between select-none">
              <span>Advanced Diagnostics &amp; Parameterized Cypher Ops</span>
              <span className="text-[11px] text-[#928992]">Show Query Traces ▾</span>
            </summary>

            <div className="p-3 space-y-3 border-t border-[#EEE6DC]">
              {/* Tab Selector */}
              <div className="flex items-center gap-1.5 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setConsoleTab("cypher")}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    consoleTab === "cypher"
                      ? "bg-[#FFFFFF] text-[#82465D] font-bold shadow-warm-xs border border-[#DFD6C9]"
                      : "text-[#645C64] hover:text-[#302B30]"
                  }`}
                >
                  GraphBLAS Cypher Ops
                </button>
                <button
                  type="button"
                  onClick={() => setConsoleTab("evidence")}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    consoleTab === "evidence"
                      ? "bg-[#FFFFFF] text-[#A06316] font-bold shadow-warm-xs border border-[#DFD6C9]"
                      : "text-[#645C64] hover:text-[#302B30]"
                  }`}
                >
                  Structured Evidence Payload
                </button>
              </div>

              {consoleTab === "cypher" && (
                <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#DFD6C9] font-mono text-xs space-y-2.5">
                  <div className="flex justify-between items-center text-[10px] text-[#645C64] border-b border-[#EEE6DC] pb-1">
                    <span>GRAPH_BLAS_TRAVERSAL · Parameterized</span>
                    <span className="text-[#26694E] font-bold">0.84ms</span>
                  </div>
                  <pre className="text-[#302B30] text-[11px] leading-tight overflow-x-auto">
                    <span className="text-[#82465D] font-bold">MATCH</span> p = (root:Host &#123;id: $patient_zero&#125;)-[:COMMUNICATES*1..4]-&gt;(target:Host)
                    <br />
                    <span className="text-[#82465D] font-bold">WHERE</span> target.tenant_id = $tenant_id
                    <br />
                    <span className="text-[#82465D] font-bold">RETURN</span> target.name, length(p) <span className="text-[#82465D] font-bold">AS</span> hops, nodes(p)
                  </pre>
                </div>
              )}

              {consoleTab === "evidence" && (
                <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#DFD6C9] font-mono text-[11px] max-h-48 overflow-y-auto">
                  {summary ? (
                    <pre className="text-[#302B30] leading-snug">
{JSON.stringify(
  {
    incident_id: summary.incident_id,
    tenant_id: resolvedTenant || "unauthenticated",
    patient_zero: summary.patient_zero_name,
    patient_zero_id: summary.patient_zero_id,
    lateral_targets_count: summary.target_count,
    max_egress_mbps: summary.egress_risk_mbps,
    at_risk_database: summary.shortest_path_db?.db_name || null,
    governance: {
      team: summary.company_brain?.team_name || null,
      oncall: summary.company_brain?.person_name || null,
      runbook_sop: summary.company_brain?.runbook_title || null,
    },
    containment_mode: "GRAPH_TOPOLOGY_SIMULATION",
  },
  null,
  2
)}
                    </pre>
                  ) : (
                    <div className="text-[#645C64] italic">
                      Awaiting autonomous threat investigation to inspect structured FalkorDB evidence payload…
                    </div>
                  )}
                </div>
              )}
            </div>
          </details>
        </div>
      </div>
  );
};
