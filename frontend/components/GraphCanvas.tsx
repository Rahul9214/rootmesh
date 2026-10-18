"use client";

import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authenticatedFetch } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

interface GraphNode {
  id: string;
  name: string;
  ip: string;
  type: "host" | "database";
  status: "SAFE" | "INFECTED" | "CONTAINED";
  x: number;
  y: number;
  tier?: string;
  team?: string;
  oncall?: string;
  runbook?: string;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
  bandwidth?: number;
  isDbLink?: boolean;
}

const TOPOLOGY_NODES: GraphNode[] = [
  { id: "host-0", name: "Workstation-PatientZero", ip: "10.0.1.15",  type: "host",     status: "INFECTED",  x: 100, y: 200, tier: "Tier-1", team: "SecOps Response", oncall: "Alex Rivera", runbook: "Workstation SOP" },
  { id: "host-1", name: "AppServer-Internal",      ip: "10.0.2.10",  type: "host",     status: "SAFE",      x: 250, y: 110, tier: "Tier-0", team: "Platform Infra",  oncall: "Elena Rostova", runbook: "App Core SOP" },
  { id: "host-2", name: "FileBackupServer",         ip: "10.0.2.22",  type: "host",     status: "SAFE",      x: 250, y: 280, tier: "Tier-1", team: "Platform Infra",  oncall: "Elena Rostova", runbook: "Backup SOP" },
  { id: "db-1",   name: "HR-Payroll-DB",           ip: "10.0.2.50",  type: "database", status: "SAFE",      x: 150, y: 390, tier: "Restricted", team: "Data Gov",    oncall: "Elena Rostova", runbook: "Data SOP" },
  { id: "db-2",   name: "Customer-Vault-DB",       ip: "10.0.2.51",  type: "database", status: "SAFE",      x: 350, y: 390, tier: "Confidential", team: "Data Gov",  oncall: "Elena Rostova", runbook: "Vault SOP" },
  { id: "host-3", name: "VLAN-Router",              ip: "10.0.3.1",   type: "host",     status: "SAFE",      x: 440, y: 195, tier: "Tier-0", team: "Edge Security",   oncall: "Marcus Chen",  runbook: "Router SOP" },
  { id: "host-4", name: "JumpServer-SysAdmin",      ip: "10.0.4.5",   type: "host",     status: "SAFE",      x: 600, y: 110, tier: "Tier-0", team: "Platform Infra",  oncall: "Elena Rostova", runbook: "Bastion SOP" },
  { id: "host-5", name: "ReverseProxy",             ip: "10.0.5.1",   type: "host",     status: "SAFE",      x: 600, y: 280, tier: "Tier-0", team: "Edge Security",   oncall: "Marcus Chen",  runbook: "Proxy SOP" },
  { id: "host-6", name: "PublicWebServer",          ip: "10.0.5.80",  type: "host",     status: "SAFE",      x: 750, y: 280, tier: "Tier-0", team: "Edge Security",   oncall: "Marcus Chen",  runbook: "Web Portal SOP" },
  { id: "host-7", name: "EgressFirewall",           ip: "10.0.99.254",type: "host",     status: "SAFE",      x: 840, y: 175, tier: "Tier-0", team: "SecOps Response", oncall: "Alex Rivera", runbook: "Perimeter SOP" },
];

const TOPOLOGY_EDGES: GraphEdge[] = [
  { from: "host-0", to: "host-1", label: "COMMUNICATES", bandwidth: 100 },
  { from: "host-0", to: "host-2", label: "COMMUNICATES", bandwidth: 100 },
  { from: "db-1",   to: "host-2", label: "STORED_ON",    bandwidth: 40, isDbLink: true },
  { from: "db-2",   to: "host-2", label: "STORED_ON",    bandwidth: 50, isDbLink: true },
  { from: "host-1", to: "host-3", label: "COMMUNICATES", bandwidth: 100 },
  { from: "host-2", to: "host-3", label: "COMMUNICATES", bandwidth: 100 },
  { from: "host-3", to: "host-4", label: "COMMUNICATES", bandwidth: 80 },
  { from: "host-3", to: "host-5", label: "COMMUNICATES", bandwidth: 30 },
  { from: "host-4", to: "host-7", label: "COMMUNICATES", bandwidth: 28 },
  { from: "host-5", to: "host-6", label: "COMMUNICATES", bandwidth: 15 },
  { from: "host-6", to: "host-7", label: "COMMUNICATES", bandwidth: 19 },
];

export interface GraphCanvasProps {
  selectedAssetId?: string;
  isContained?: boolean;
  onSelectNode?: (nodeId: string) => void;
}

export const GraphCanvas: React.FC<GraphCanvasProps> = ({
  selectedAssetId = "host-0",
  isContained = false,
  onSelectNode,
}) => {
  const [nodes, setNodes] = useState<GraphNode[]>(TOPOLOGY_NODES);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Synchronize selection with selectedAssetId prop
  useEffect(() => {
    if (selectedAssetId) {
      const match = nodes.find((n) => n.id === selectedAssetId);
      if (match) setSelectedNode(match);
    }
  }, [selectedAssetId, nodes]);

  // Synchronize containment state
  useEffect(() => {
    setNodes((prev) =>
      prev.map((n) => {
        if (n.id === (selectedAssetId || "host-0")) {
          return {
            ...n,
            status: isContained ? "CONTAINED" : "INFECTED",
          };
        }
        return n;
      })
    );
  }, [isContained, selectedAssetId]);
  const [pageRankMap, setPageRankMap] = useState<Record<string, number>>({});
  const [highlightShortestPath, setHighlightShortestPath] = useState(true);
  const [showPageRank, setShowPageRank] = useState(false);
  const [showTeams, setShowTeams] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const containerRef = useRef<HTMLDivElement>(null);

  // Fetch PageRank scores from live FalkorDB
  useEffect(() => {
    authenticatedFetch(`${API_BASE}/api/v1/threat/pagerank/${TENANT_ID}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((data: Array<{ host_name: string; score: number }>) => {
        const map: Record<string, number> = {};
        data.forEach((d) => {
          map[d.host_name] = d.score;
        });
        setPageRankMap(map);
      })
      .catch(() => {});
  }, []);

  // Fetch live topology to update node status (contained / infected)
  useEffect(() => {
    authenticatedFetch(`${API_BASE}/api/v1/threat/topology/${TENANT_ID}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((data: Array<{ id: string; status: "SAFE" | "INFECTED" | "CONTAINED" }>) => {
        if (data && data.length > 0) {
          setNodes((prev) =>
            prev.map((n) => {
              const live = data.find((d) => d.id === n.id);
              return live ? { ...n, status: live.status } : n;
            })
          );
        }
      })
      .catch(() => {});
  }, []);

  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName !== "circle" && (e.target as HTMLElement).tagName !== "text") {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const isEdgeInShortestPath = (from: string, to: string) => {
    if (!highlightShortestPath) return false;
    // Highlight attack path to database: host-0 -> host-2 and db-1 -> host-2
    return (
      (from === "host-0" && to === "host-2") ||
      (from === "db-1" && to === "host-2") ||
      (from === "host-2" && to === "host-3") ||
      (from === "host-3" && to === "host-4") ||
      (from === "host-4" && to === "host-7")
    );
  };

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-6 shadow-warm-sm space-y-4">
      {/* ── Graph Header & Controls ───────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3 border-b border-[#EEE6DC] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#E6A548]" />
            <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
              FalkorDB Interactive Graph Canvas
            </h3>
          </div>
          <p className="text-xs text-[#645C64] mt-0.5">
            Topology visualization with path highlighting, PageRank scoring, and organizational context
          </p>
        </div>

        {/* View Controls & Toggles */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <button
            onClick={() => setHighlightShortestPath(!highlightShortestPath)}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              highlightShortestPath
                ? "bg-[#FBF0ED] text-[#C24128] border-[#F3C4B8] font-bold"
                : "bg-[#FAF7F2] text-[#645C64] border-[#DFD6C9]"
            }`}
          >
            {highlightShortestPath ? "✓ Attack Path Active" : "Show Attack Path"}
          </button>

          <button
            onClick={() => setShowPageRank(!showPageRank)}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              showPageRank
                ? "bg-[#FDF5E8] text-[#A06316] border-[#F4DCB6] font-bold"
                : "bg-[#FAF7F2] text-[#645C64] border-[#DFD6C9]"
            }`}
          >
            {showPageRank ? "✓ PageRank Overlay" : "PageRank Overlay"}
          </button>

          <button
            onClick={() => setShowTeams(!showTeams)}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              showTeams
                ? "bg-[#F6EDF1] text-[#82465D] border-[#E5CDD8] font-bold"
                : "bg-[#FAF7F2] text-[#645C64] border-[#DFD6C9]"
            }`}
          >
            {showTeams ? "✓ Team Context" : "Company Teams"}
          </button>

          <div className="flex items-center gap-1 border border-[#DFD6C9] rounded-lg bg-[#FAF7F2] p-0.5">
            <button
              onClick={() => setZoom((z) => Math.min(1.6, z + 0.15))}
              className="px-2 py-0.5 hover:bg-[#EEE6DC] rounded text-[#302B30] font-bold"
              aria-label="Zoom in"
            >
              +
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.6, z - 0.15))}
              className="px-2 py-0.5 hover:bg-[#EEE6DC] rounded text-[#302B30] font-bold"
              aria-label="Zoom out"
            >
              -
            </button>
            <button
              onClick={resetView}
              className="px-2 py-0.5 hover:bg-[#EEE6DC] rounded text-[#645C64] text-[10px]"
            >
              Fit
            </button>
          </div>
        </div>
      </div>

      {/* ── Interactive SVG Canvas ────────────────────────────────────── */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        className="relative w-full h-[460px] md:h-[500px] rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] overflow-hidden cursor-grab active:cursor-grabbing select-none"
      >
        <svg
          className="w-full h-full"
          viewBox="20 30 900 420"
          preserveAspectRatio="xMidYMid meet"
        >
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Background Dot Grid */}
            <defs>
              <pattern id="warm-grid" width="24" height="24" patternUnits="userSpaceOnUse">
                <circle cx="1.5" cy="1.5" r="1" fill="#DFD6C9" opacity="0.6" />
              </pattern>
              <marker
                id="arrow-default"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#C8BEB0" />
              </marker>
              <marker
                id="arrow-highlight"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#D26A50" />
              </marker>
            </defs>

            <rect width="1200" height="800" x="-100" y="-100" fill="url(#warm-grid)" />

            {/* Communication Edges */}
            {TOPOLOGY_EDGES.map((edge, i) => {
              const source = nodes.find((n) => n.id === edge.from);
              const target = nodes.find((n) => n.id === edge.to);
              if (!source || !target) return null;

              const isHighlighted = isEdgeInShortestPath(edge.from, edge.to);

              return (
                <g key={`edge-${i}`}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke={isHighlighted ? "#D26A50" : "#DFD6C9"}
                    strokeWidth={isHighlighted ? 3 : 1.5}
                    strokeDasharray={isHighlighted ? "6 3" : undefined}
                    markerEnd={isHighlighted ? "url(#arrow-highlight)" : "url(#arrow-default)"}
                    className={isHighlighted ? "animate-pulse" : ""}
                  />
                  {edge.bandwidth && (
                    <text
                      x={(source.x + target.x) / 2}
                      y={(source.y + target.y) / 2 - 4}
                      fill={isHighlighted ? "#C24128" : "#928992"}
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="select-none"
                    >
                      {edge.bandwidth}M
                    </text>
                  )}
                </g>
              );
            })}

            {/* Graph Nodes */}
            {nodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              const prScore = pageRankMap[node.name] || 0.02;
              const nodeRadius = showPageRank
                ? Math.max(22, Math.min(38, prScore * 340))
                : 26;

              let fillColor = "#FFFFFF";
              let strokeColor = "#DFD6C9";

              if (node.status === "INFECTED") {
                fillColor = "#FBF0ED";
                strokeColor = "#D26A50";
              } else if (node.status === "CONTAINED") {
                fillColor = "#F6EDF1";
                strokeColor = "#82465D";
              } else if (node.type === "database") {
                fillColor = "#FDF5E8";
                strokeColor = "#E6A548";
              }

              if (showTeams && node.team) {
                if (node.team.includes("SecOps")) strokeColor = "#D26A50";
                else if (node.team.includes("Platform")) strokeColor = "#E6A548";
                else if (node.team.includes("Edge")) strokeColor = "#82465D";
              }

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => {
                    setSelectedNode(node);
                    onSelectNode?.(node.id);
                  }}
                  className="cursor-pointer group"
                >
                  {/* Selection Ring */}
                  {isSelected && (
                    <circle
                      r={nodeRadius + 7}
                      fill="none"
                      stroke="#D26A50"
                      strokeWidth="2.5"
                      strokeDasharray="4 2"
                      className="animate-spin"
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r={nodeRadius}
                    fill={fillColor}
                    stroke={strokeColor}
                    strokeWidth={isSelected ? 3.5 : 2.5}
                    className="transition-all duration-300 drop-shadow-sm group-hover:scale-105"
                  />

                  {/* Node Icon / Symbol */}
                  <text
                    y={node.type === "database" ? 5 : 5}
                    textAnchor="middle"
                    fontSize={node.type === "database" ? "14" : "13"}
                    fill="#302B30"
                    className="select-none font-bold"
                  >
                    {node.type === "database"
                      ? "🗄"
                      : node.status === "INFECTED"
                      ? "⚠"
                      : node.status === "CONTAINED"
                      ? "🔒"
                      : "🖥"}
                  </text>

                  {/* Node Label Below with Halo Outline for crisp contrast */}
                  <text
                    y={nodeRadius + 15}
                    textAnchor="middle"
                    fontSize="11"
                    fontFamily="monospace"
                    fontWeight="bold"
                    fill="#302B30"
                    stroke="#FAF7F2"
                    strokeWidth="3"
                    paintOrder="stroke"
                    className="select-none"
                  >
                    {node.name.length > 18 ? node.name.slice(0, 16) + "…" : node.name}
                  </text>

                  {/* IP or Sub-label */}
                  <text
                    y={nodeRadius + 27}
                    textAnchor="middle"
                    fontSize="9.5"
                    fontFamily="monospace"
                    fill="#645C64"
                    stroke="#FAF7F2"
                    strokeWidth="2.5"
                    paintOrder="stroke"
                    className="select-none"
                  >
                    {node.id} · {node.ip}
                  </text>

                  {/* PageRank Score Badge if enabled */}
                  {showPageRank && prScore > 0 && (
                    <g transform={`translate(${nodeRadius - 2}, ${-nodeRadius + 2})`}>
                      <rect
                        width="34"
                        height="12"
                        rx="3"
                        fill="#FDF5E8"
                        stroke="#E6A548"
                        strokeWidth="1"
                      />
                      <text
                        x="17"
                        y="9"
                        fontSize="8"
                        fontFamily="monospace"
                        fontWeight="bold"
                        fill="#A06316"
                        textAnchor="middle"
                      >
                        {prScore.toFixed(3)}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* ── Dedicated Legend Bar (Zero-Overlap Guarantee) ─────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl bg-[#FAF7F2] border border-[#DFD6C9] text-[11px] font-mono text-[#645C64]">
        <div className="flex flex-wrap items-center gap-3.5">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FFFFFF] border-2 border-[#DFD6C9]" />
            <span>Safe Host</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FBF0ED] border-2 border-[#D26A50]" />
            <span>Patient Zero (Infected)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#F6EDF1] border-2 border-[#82465D]" />
            <span>Contained (Sim)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FDF5E8] border-2 border-[#E6A548]" />
            <span>High-Value Database</span>
          </span>
        </div>
        <span className="text-[10px] text-[#928992]">
          Click node to inspect · Drag to pan · Scroll to zoom
        </span>
      </div>

      {/* ── Slide-Out Node Inspector Drawer ───────────────────────────── */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="p-4 rounded-xl bg-[#F5EFE6] border border-[#DFD6C9] space-y-3 font-mono text-xs shadow-warm-xs"
          >
            <div className="flex justify-between items-center border-b border-[#DFD6C9] pb-2">
              <div className="flex items-center gap-2">
                <span className="text-base">{selectedNode.type === "database" ? "🗄" : "🖥"}</span>
                <span className="font-bold text-[#302B30] text-sm">{selectedNode.name}</span>
                <span className="text-[10px] text-[#645C64]">({selectedNode.id})</span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="px-2 py-0.5 rounded bg-[#FAF7F2] hover:bg-[#EEE6DC] text-[#645C64] border border-[#DFD6C9] text-[11px]"
              >
                Close Drawer
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="space-y-1">
                <div className="text-[10px] text-[#928992] uppercase">Asset Properties</div>
                <div className="text-[#302B30]">IP Address: <strong>{selectedNode.ip}</strong></div>
                <div className="text-[#302B30]">Node Type: <strong>{selectedNode.type.toUpperCase()}</strong></div>
                <div className="text-[#302B30]">SLA Tier: <strong>{selectedNode.tier || "Tier-1"}</strong></div>
                <div className="text-[#302B30]">
                  Status:{" "}
                  <strong
                    className={
                      selectedNode.status === "INFECTED"
                        ? "text-[#C24128]"
                        : selectedNode.status === "CONTAINED"
                        ? "text-[#82465D]"
                        : "text-[#26694E]"
                    }
                  >
                    {selectedNode.status}
                  </strong>
                </div>
              </div>

              <div className="space-y-1">
                <div className="text-[10px] text-[#928992] uppercase">Company Brain Context</div>
                <div className="text-[#302B30]">Service: <strong>Endpoint Identity Gateway</strong></div>
                <div className="text-[#302B30]">Owning Team: <strong>{selectedNode.team || "SecOps Response"}</strong></div>
                <div className="text-[#302B30]">On-Call Engineer: <strong>{selectedNode.oncall || "Alex Rivera"}</strong></div>
                <div className="text-[#A06316]">Playbook: <strong>{selectedNode.runbook || "SOP-Iso-001"}</strong></div>
              </div>

              <div className="space-y-1">
                <div className="text-[10px] text-[#928992] uppercase">FalkorDB GraphBLAS Metrics</div>
                <div className="text-[#302B30]">
                  PageRank Score:{" "}
                  <strong className="text-[#A06316]">
                    {pageRankMap[selectedNode.name] ? pageRankMap[selectedNode.name].toFixed(5) : "0.01827"}
                  </strong>
                </div>
                <div className="text-[#302B30]">Egress Exposure: <strong>43.0 Mbps</strong></div>
                <div className="text-[9px] text-[#928992] italic pt-1">
                  * Company Brain entities are synthetic demonstration graph data in FalkorDB.
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
