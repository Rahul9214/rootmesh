"use client";

import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

interface PageRankEntry {
  host_name: string;
  ip: string;
  score: number;
}

export const GraphCanvas: React.FC = () => {
  const [assets, setAssets] = useState<PageRankEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [falkorUrl] = useState("http://localhost:3005");

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/threat/pagerank/${TENANT_ID}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: PageRankEntry[]) => {
        setAssets(data);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, []);

  const maxScore = assets.length > 0 ? assets[0].score : 1;

  return (
    <div className="w-full rounded-2xl border border-indigo-900/40 bg-slate-950/80 backdrop-blur-md p-6 shadow-2xl">
      <div className="flex justify-between items-center mb-5">
        <div>
          <h3 className="text-sm font-semibold text-violet-300 uppercase tracking-widest">
            Critical Asset Ranking
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">FalkorDB algo.pageRank — GraphBLAS Sparse Matrix</p>
        </div>
        <a
          href={falkorUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[10px] px-3 py-1.5 rounded-lg bg-violet-950/60 text-violet-300 border border-violet-500/30 hover:bg-violet-900/40 transition-colors font-mono"
        >
          Open FalkorDB Canvas ↗
        </a>
      </div>

      {loading && (
        <div className="flex items-center justify-center h-40">
          <div className="w-6 h-6 rounded-full border-2 border-violet-500 border-t-transparent animate-spin" />
        </div>
      )}

      {error && (
        <div className="text-xs text-rose-400 font-mono text-center py-8">
          ⚠ Could not fetch PageRank data: {error}
          <br />
          <span className="text-slate-500">Ensure backend + FalkorDB Docker stack is running.</span>
        </div>
      )}

      {!loading && !error && (
        <div className="space-y-3">
          {assets.map((asset, i) => {
            const barWidth = Math.max(5, (asset.score / maxScore) * 100);
            const isTop = i === 0;
            return (
              <motion.div
                key={asset.host_name}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.06 }}
                className={`relative p-3 rounded-xl border ${isTop ? "border-amber-500/50 bg-amber-950/20" : "border-slate-800/50 bg-slate-900/40"}`}
              >
                <div className="flex justify-between items-center mb-2">
                  <span className="flex items-center gap-2">
                    {isTop && <span className="text-amber-400 text-xs">🔥</span>}
                    <span className="text-xs font-semibold text-slate-200">{asset.host_name}</span>
                  </span>
                  <div className="text-right">
                    <span className={`text-xs font-mono font-bold ${isTop ? "text-amber-400" : "text-violet-400"}`}>
                      {asset.score.toFixed(5)}
                    </span>
                    <span className="text-[10px] text-slate-500 ml-1">PR</span>
                  </div>
                </div>
                <div className="h-1.5 rounded-full bg-slate-800">
                  <motion.div
                    className={`h-full rounded-full ${isTop ? "bg-gradient-to-r from-amber-500 to-rose-500" : "bg-gradient-to-r from-violet-600 to-indigo-500"}`}
                    initial={{ width: 0 }}
                    animate={{ width: `${barWidth}%` }}
                    transition={{ duration: 0.8, delay: i * 0.08 }}
                  />
                </div>
                <span className="text-[10px] text-slate-600 font-mono mt-1 block">{asset.ip}</span>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
};
