/**
 * RootMesh Frontend — System Health & Connectivity Client
 * Safely probes the public /health endpoint to monitor backend and FalkorDB GraphBLAS state.
 * Never conflates authentication/authorization failures (401/403) with database connectivity.
 */

import { getApiBase } from "./auth";

export interface SystemHealth {
  status: "checking" | "operational" | "degraded" | "offline";
  database: string;
  engine: string;
  environment?: string;
  version?: string;
  checkedAt: number;
}

const DEFAULT_HEALTH: SystemHealth = {
  status: "checking",
  database: "unknown",
  engine: "FalkorDB GraphBLAS",
  checkedAt: 0,
};

let cachedHealth: SystemHealth = { ...DEFAULT_HEALTH };
const healthListeners = new Set<(health: SystemHealth) => void>();

function notifyHealthListeners() {
  healthListeners.forEach((fn) => {
    try {
      fn(cachedHealth);
    } catch {}
  });
}

export async function checkSystemHealth(): Promise<SystemHealth> {
  const apiBase = getApiBase();
  try {
    const res = await fetch(`${apiBase}/health`, {
      method: "GET",
      cache: "no-store",
    });

    if (res.ok) {
      const data = await res.json();
      cachedHealth = {
        status: data.database === "operational" ? "operational" : "degraded",
        database: data.database || "operational",
        engine: data.engine || "FalkorDB GraphBLAS",
        environment: data.environment,
        version: data.version,
        checkedAt: Date.now(),
      };
    } else {
      cachedHealth = {
        status: "degraded",
        database: "unreachable",
        engine: "FalkorDB GraphBLAS",
        checkedAt: Date.now(),
      };
    }
  } catch {
    cachedHealth = {
      status: "offline",
      database: "offline",
      engine: "FalkorDB GraphBLAS",
      checkedAt: Date.now(),
    };
  }

  notifyHealthListeners();
  return cachedHealth;
}

export function onSystemHealthChanged(fn: (health: SystemHealth) => void): () => void {
  healthListeners.add(fn);
  fn(cachedHealth);
  return () => {
    healthListeners.delete(fn);
  };
}

export function getCachedSystemHealth(): SystemHealth {
  return cachedHealth;
}
