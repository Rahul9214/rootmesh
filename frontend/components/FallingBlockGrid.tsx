"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authenticatedFetch, getAuthenticatedWebSocketUrl } from "@/lib/auth";

interface ThreatNode {
  id: string;
  name: string;
  ip: string;
  status: "SAFE" | "INFECTED" | "CONTAINED";
  hops: number;
}

const INITIAL_NODES: ThreatNode[] = [
  { id: "host-0", name: "Workstation-PatientZero", ip: "10.0.1.15",  status: "INFECTED", hops: 0 },
  { id: "host-1", name: "AppServer-Internal",      ip: "10.0.2.10",  status: "SAFE",     hops: 1 },
  { id: "host-2", name: "FileBackupServer",         ip: "10.0.2.22",  status: "SAFE",     hops: 1 },
  { id: "host-3", name: "VLAN-Router",              ip: "10.0.3.1",   status: "SAFE",     hops: 2 },
  { id: "host-4", name: "JumpServer-SysAdmin",      ip: "10.0.4.5",   status: "SAFE",     hops: 3 },
  { id: "host-5", name: "ReverseProxy",             ip: "10.0.5.1",   status: "SAFE",     hops: 3 },
  { id: "host-6", name: "PublicWebServer",          ip: "10.0.5.80",  status: "SAFE",     hops: 4 },
  { id: "host-7", name: "EgressFirewall",           ip: "10.0.99.254",status: "SAFE",     hops: 4 },
];

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TENANT_ID = "sec_ops_tenant_alpha";

const statusStyles: Record<ThreatNode["status"], string> = {
  INFECTED:  "bg-rose-950/50  border-rose-500/80  shadow-[0_0_18px_rgba(244,63,94,0.4)]",
  CONTAINED: "bg-amber-950/40 border-amber-500/70 shadow-[0_0_12px_rgba(255,184,0,0.3)]",
  SAFE:      "bg-indigo-950/30 border-indigo-800/40 hover:border-violet-500/50",
};

const badgeStyles: Record<ThreatNode["status"], string> = {
  INFECTED:  "bg-rose-500/20  text-rose-300  border border-rose-500/40",
  CONTAINED: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
  SAFE:      "bg-emerald-500/20 text-emerald-300",
};

export const FallingBlockGrid: React.FC = () => {
  const [nodes, setNodes] = useState<ThreatNode[]>(INITIAL_NODES);
  const [wsStatus, setWsStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const [containingId, setContainingId] = useState<string | null>(null);

  // Fetch live topology directly from FalkorDB on mount
  useEffect(() => {
    authenticatedFetch(`${API_BASE}/api/v1/threat/topology/${TENANT_ID}`)
      .then((r) => r.ok ? r.json() : null)
      .then((data: ThreatNode[] | null) => {
        if (data && data.length > 0) {
          setNodes(data);
        }
      })
      .catch(() => {
        // Fall back to INITIAL_NODES if offline
      });
  }, []);

  // Execute real backend graph containment in FalkorDB
  const handleContain = useCallback(async (id: string) => {
    setContainingId(id);
    try {
      const res = await authenticatedFetch(`${API_BASE}/api/v1/threat/contain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: TENANT_ID,
          host_id: id,
        }),
      });
      if (res.ok) {
        setNodes((prev) =>
          prev.map((n) => (n.id === id ? { ...n, status: "CONTAINED" } : n))
        );
      }
    } catch {
      // Keep state unchanged on failure
    } finally {
      setContainingId(null);
    }
  }, []);

  useEffect(() => {
    let ws: WebSocket;
    let retryTimer: ReturnType<typeof setTimeout>;

    const connect = async () => {
      try {
        const url = await getAuthenticatedWebSocketUrl("/ws/threat-stream", TENANT_ID);
        ws = new WebSocket(url);
        ws.onopen = () => setWsStatus("live");
        ws.onclose = () => {
          setWsStatus("offline");
          retryTimer = setTimeout(connect, 3000);
        };
        ws.onerror = () => setWsStatus("offline");
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.event === "ATTACK_PROPAGATION_COMPUTED") {
              setNodes((prev) =>
                prev.map((n) =>
                  n.id !== data.patient_zero && n.status === "SAFE"
                    ? { ...n, status: "INFECTED" }
                    : n
                )
              );
            }
          } catch {}
        };
      } catch {
        setWsStatus("offline");
      }
    };

    connect();
    return () => {
      ws?.close();
      clearTimeout(retryTimer);
    };
  }, []);

  const infected = nodes.filter((n) => n.status === "INFECTED").length;
  const contained = nodes.filter((n) => n.status === "CONTAINED").length;

  return (
    <div className="w-full rounded-2xl border border-indigo-900/40 bg-slate-950/80 backdrop-blur-md p-6 shadow-2xl">
      {/* Header */}
      <div className="flex flex-wrap justify-between items-center mb-5 gap-3">
        <div>
          <h3 className="text-sm font-semibold text-violet-300 uppercase tracking-widest">
            Live Threat Propagation
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">FalkorDB GraphBLAS Real-Time Traversal</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <span className={`flex items-center gap-1.5 ${wsStatus === "live" ? "text-emerald-400" : wsStatus === "connecting" ? "text-amber-400" : "text-rose-400"}`}>
            <span className={`w-2 h-2 rounded-full ${wsStatus === "live" ? "bg-emerald-500 animate-ping" : wsStatus === "connecting" ? "bg-amber-400 animate-pulse" : "bg-rose-500"}`} />
            {wsStatus === "live" ? "RESP Connected" : wsStatus === "connecting" ? "Connecting…" : "Reconnecting…"}
          </span>
          <span className="text-rose-400">⚠ {infected} Infected</span>
          <span className="text-amber-400">🔒 {contained} Contained (Graph Sim)</span>
        </div>
      </div>

      {/* Block Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        <AnimatePresence>
          {nodes.map((node, index) => (
            <motion.div
              key={node.id}
              initial={{ y: -80, opacity: 0, scale: 0.75 }}
              animate={{ y: 0, opacity: 1, scale: 1 }}
              exit={{ y: 80, opacity: 0 }}
              transition={{ duration: 0.55, delay: index * 0.08, type: "spring", stiffness: 140 }}
              className={`relative p-4 rounded-xl border backdrop-blur-md flex flex-col justify-between h-32 transition-colors duration-500 ${statusStyles[node.status]}`}
            >
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-mono text-slate-500">{node.id}</span>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase ${badgeStyles[node.status]}`}>
                  {node.status === "CONTAINED" ? "CONTAINED (SIM)" : node.status}
                </span>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-100 leading-tight mt-1">{node.name}</p>
                <p className="text-[10px] text-slate-500 font-mono">{node.ip}</p>
              </div>
              <div className="flex justify-between items-center mt-2">
                <span className="text-[10px] text-indigo-400 font-mono">Hop {node.hops}</span>
                {node.status === "INFECTED" && (
                  <button
                    onClick={() => handleContain(node.id)}
                    disabled={containingId === node.id}
                    className="text-[9px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/40 transition-colors disabled:opacity-50"
                  >
                    {containingId === node.id ? "Isolating…" : "Contain (Sim)"}
                  </button>
                )}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};
