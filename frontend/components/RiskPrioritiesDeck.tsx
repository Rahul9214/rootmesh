"use client";

import React, { useState } from "react";

export interface PriorityAsset {
  id: string;
  name: string;
  ip: string;
  rank: number;
  pagerankScore: number;
  reachabilityHops: number;
  criticalityReason: string;
  serviceName: string;
  owningTeam: string;
  oncallResponder: string;
  cves: string[];
  recommendedAction: string;
}

interface RiskPrioritiesDeckProps {
  selectedAssetId?: string;
  onSelectAsset?: (assetId: string) => void;
}

const RANKED_ASSETS: PriorityAsset[] = [
  {
    id: "host-7",
    name: "EgressFirewall",
    ip: "10.0.99.254",
    rank: 1,
    pagerankScore: 0.0649,
    reachabilityHops: 4,
    criticalityReason: "Rank #1 by FalkorDB GraphBLAS PageRank (0.0649). Primary perimeter egress sink and destination for the 43.0 Mbps MaxFlow bottleneck.",
    serviceName: "Perimeter Egress Firewall Service (svc-perimeter-fw)",
    owningTeam: "SecOps Incident Response",
    oncallResponder: "Alex Rivera (Lead Incident Responder)",
    cves: [],
    recommendedAction: "Execute Perimeter Port Isolation & Shunt Egress",
  },
  {
    id: "host-3",
    name: "VLAN-Router",
    ip: "10.0.3.1",
    rank: 2,
    pagerankScore: 0.0389,
    reachabilityHops: 2,
    criticalityReason: "Rank #2 by FalkorDB GraphBLAS PageRank (0.0389). Core network routing transit switch connecting all lateral subnet vectors.",
    serviceName: "VLAN Routing & SDN Core (svc-network-mesh)",
    owningTeam: "Platform Infrastructure Engineering",
    oncallResponder: "Elena Rostova (Staff Platform Architect)",
    cves: [],
    recommendedAction: "Apply Zero-Trust ACL & Shunt Transit Subnets",
  },
  {
    id: "host-6",
    name: "PublicWebServer",
    ip: "10.0.5.80",
    rank: 3,
    pagerankScore: 0.0351,
    reachabilityHops: 4,
    criticalityReason: "Rank #3 by FalkorDB GraphBLAS PageRank (0.0351). Public-facing ingress portal and customer web endpoint.",
    serviceName: "Public Web Portal & Customer Gateway (svc-web-portal)",
    owningTeam: "Edge Ingress & Gateway Security",
    oncallResponder: "Marcus Chen (Edge Security Engineer)",
    cves: [],
    recommendedAction: "Deploy WAF Rate-Limiting & Restrict Ingress",
  },
  {
    id: "host-4",
    name: "JumpServer-SysAdmin",
    ip: "10.0.4.5",
    rank: 4,
    pagerankScore: 0.0279,
    reachabilityHops: 3,
    criticalityReason: "Rank #4 by FalkorDB GraphBLAS PageRank (0.0279). Privileged administrative jump bastion with high connectivity to internal infrastructure.",
    serviceName: "Privileged Access Bastion (svc-bastion)",
    owningTeam: "Platform Infrastructure Engineering",
    oncallResponder: "Elena Rostova (Staff Platform Architect)",
    cves: [],
    recommendedAction: "Terminate Idle Bastion Jump Sessions & Rotate Credentials",
  },
  {
    id: "host-5",
    name: "ReverseProxy",
    ip: "10.0.5.1",
    rank: 5,
    pagerankScore: 0.0279,
    reachabilityHops: 3,
    criticalityReason: "Rank #5 by FalkorDB GraphBLAS PageRank (0.0279). Edge TLS termination reverse proxy gateway routing ingress to internal tiers.",
    serviceName: "Reverse Proxy & TLS Ingress (svc-proxy)",
    owningTeam: "Edge Ingress & Gateway Security",
    oncallResponder: "Marcus Chen (Edge Security Engineer)",
    cves: [],
    recommendedAction: "Shunt Ingress Traffic & Tighten Proxy TLS Handshake Policy",
  },
  {
    id: "host-2",
    name: "FileBackupServer",
    ip: "10.0.2.22",
    rank: 6,
    pagerankScore: 0.0162,
    reachabilityHops: 1,
    criticalityReason: "Rank #6 by FalkorDB GraphBLAS PageRank (0.0162). Direct 1-hop reachability from Patient Zero; co-locates HR-Payroll-DB (PII_RESTRICTED).",
    serviceName: "Secure Backup & Archive Service (svc-backup)",
    owningTeam: "Platform Infrastructure Engineering",
    oncallResponder: "Elena Rostova (Staff Platform Architect)",
    cves: [],
    recommendedAction: "Quarantine Backup Volume & Revoke DB Session Tokens",
  },
  {
    id: "host-1",
    name: "AppServer-Internal",
    ip: "10.0.2.10",
    rank: 7,
    pagerankScore: 0.0162,
    reachabilityHops: 1,
    criticalityReason: "Rank #7 by FalkorDB GraphBLAS PageRank (0.0162). Direct 1-hop reachability from Patient Zero; carries active vulnerability CVE-2021-44228 (Log4Shell).",
    serviceName: "Internal Application Core API (svc-app-core)",
    owningTeam: "Platform Infrastructure Engineering",
    oncallResponder: "Elena Rostova (Staff Platform Architect)",
    cves: ["CVE-2021-44228 (Log4Shell RCE)"],
    recommendedAction: "Isolate Host Network Interface & Snapshot Memory",
  },
];

export const RiskPrioritiesDeck: React.FC<RiskPrioritiesDeckProps> = ({
  selectedAssetId = "host-7",
  onSelectAsset,
}) => {
  const [activeAssetId, setActiveAssetId] = useState<string>(selectedAssetId);
  const activeAsset = RANKED_ASSETS.find((a) => a.id === activeAssetId) || RANKED_ASSETS[0];

  const handleSelect = (asset: PriorityAsset) => {
    setActiveAssetId(asset.id);
    if (onSelectAsset) {
      onSelectAsset(asset.id);
    }
  };

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-6 shadow-warm-sm space-y-5">
      {/* ── Section Header ────────────────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3 border-b border-[#EEE6DC] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#E6A548]" />
            <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
              Risk Priorities: Connected Exposure Insights
            </h3>
          </div>
          <p className="text-xs text-[#645C64] mt-0.5">
            Ranked strictly by FalkorDB GraphBLAS PageRank centrality (ORDER BY score DESC). Reachability distance from patient zero and high-value database associations are displayed alongside each asset as verified topological context.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-[#82465D] bg-[#FAF7F2] border border-[#DFD6C9] px-2.5 py-1 rounded-md font-bold">
            FalkorDB PageRank Centrality (ORDER BY score DESC)
          </span>
        </div>
      </div>

      {/* ── Analytical Asset Grid ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Ranked Asset Selector Cards (5 Cols) */}
        <div className="lg:col-span-5 space-y-2.5">
          {RANKED_ASSETS.map((asset) => {
            const isSelected = activeAssetId === asset.id;
            return (
              <button
                key={asset.id}
                onClick={() => handleSelect(asset)}
                className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-center justify-between font-mono text-xs ${
                  isSelected
                    ? "bg-[#FAF7F2] border-[#D26A50] shadow-warm-xs ring-1 ring-[#D26A50]"
                    : "bg-[#FFFFFF] border-[#DFD6C9] hover:border-[#82465D]/40 hover:bg-[#FAF7F2]/50"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`w-6 h-6 rounded-lg flex items-center justify-center font-bold text-[11px] ${
                      asset.rank === 1
                        ? "bg-[#D26A50] text-white"
                        : asset.rank === 2
                        ? "bg-[#E6A548] text-white"
                        : "bg-[#EEE6DC] text-[#302B30]"
                    }`}
                  >
                    #{asset.rank}
                  </span>
                  <div>
                    <h4 className="font-bold text-[#302B30]">{asset.name}</h4>
                    <span className="text-[10px] text-[#645C64]">{asset.ip}</span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="block text-[11px] font-bold text-[#82465D]">
                    PR: {asset.pagerankScore.toFixed(4)}
                  </span>
                  <span className="text-[10px] text-[#645C64]">
                    {asset.reachabilityHops} hop{asset.reachabilityHops === 1 ? "" : "s"} away
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
                Rank #{activeAsset.rank} Priority Target
              </span>
              <h4 className="text-base font-extrabold text-[#302B30]">{activeAsset.name}</h4>
              <span className="text-[11px] text-[#645C64]">{activeAsset.ip}</span>
            </div>
            <div className="text-right">
              <span className="text-[10px] text-[#928992] block uppercase">PageRank Score</span>
              <strong className="text-base font-extrabold text-[#82465D]">
                {activeAsset.pagerankScore.toFixed(4)}
              </strong>
            </div>
          </div>

          {/* Graph Evidence Explanation */}
          <div className="space-y-1.5">
            <span className="text-[10px] text-[#928992] uppercase block">Graph-Derived Risk Evidence</span>
            <p className="text-[#302B30] leading-relaxed bg-[#FFFFFF] p-3 rounded-lg border border-[#EEE6DC]">
              {activeAsset.criticalityReason}
            </p>
          </div>

          {/* Organizational Context & CVEs */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
              <span className="text-[10px] text-[#928992] uppercase block">Exposed Service</span>
              <strong className="text-[#302B30] block truncate">{activeAsset.serviceName}</strong>
              <span className="text-[10px] text-[#645C64] block">Team: {activeAsset.owningTeam}</span>
            </div>

            <div className="p-3 bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] space-y-1">
              <span className="text-[10px] text-[#928992] uppercase block">Primary Responder</span>
              <strong className="text-[#302B30] block">{activeAsset.oncallResponder}</strong>
              {activeAsset.cves.length > 0 ? (
                <span className="text-[10px] text-[#C24128] font-bold block">
                  {activeAsset.cves.join(", ")}
                </span>
              ) : (
                <span className="text-[10px] text-[#26694E] block">No direct unpatched CVE</span>
              )}
            </div>
          </div>

          {/* Recommended Response Action */}
          <div className="p-3 rounded-lg bg-[#FBF0ED] border border-[#F3C4B8] space-y-1">
            <span className="text-[10px] font-bold text-[#D26A50] uppercase block">
              Recommended Graph Response Action
            </span>
            <p className="text-xs font-bold text-[#302B30]">{activeAsset.recommendedAction}</p>
          </div>
        </div>
      </div>
    </div>
  );
};
