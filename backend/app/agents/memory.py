"""
RootMesh — Forensic Memory Agent (Track 2 Agent Memory & Coordination)
Persists episodic incident findings as subgraphs (:Finding)-[:ABOUT]->(:Host),
enforces multi-tenant graph isolation, and recalls historical memory across sessions.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from app.db.falkor_client import db_pool
from app.db import queries

logger = logging.getLogger("RootMesh-MemoryAgent")


class MemoryAgent:
    """Manages episodic and procedural agent threat memory in FalkorDB."""

    def __init__(self, tenant_id: str = "sec_ops_tenant_alpha") -> None:
        self.tenant_id = tenant_id

    def persist_finding(
        self,
        host_id: str,
        text: str,
        severity: str = "HIGH",
        session_id: str = "incident-session",
        confidence: float = 0.95,
    ) -> Dict[str, Any]:
        """
        Persists an agent finding node connected to the impacted host.
        Enables multi-session episodic memory persistence.
        """
        t0 = time.perf_counter()
        graph = db_pool.get_tenant_graph(self.tenant_id)

        res = graph.query(
            queries.PERSIST_FINDING,
            {
                "host_id": host_id,
                "text": text,
                "severity": severity,
                "session_id": session_id,
                "confidence": confidence,
            },
        ).result_set

        finding_id = res[0][0] if res else "unknown"
        exec_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "finding_id": finding_id,
            "host_id": host_id,
            "severity": severity,
            "session_id": session_id,
            "tenant_id": self.tenant_id,
            "execution_time_ms": exec_ms,
        }

    def recall_host_memory(self, host_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Recalls historical incident findings recorded for a specific host
        across prior investigation sessions.
        """
        graph = db_pool.get_tenant_graph(self.tenant_id)
        cypher = """
        MATCH (f:Finding)-[:ABOUT]->(h:Host {id: $hid})
        RETURN f.id, f.text, f.severity, f.session_id, f.at
        ORDER BY f.at DESC
        LIMIT $limit
        """
        res = graph.ro_query(cypher, {"hid": host_id, "limit": limit}).result_set
        return [
            {
                "finding_id": r[0],
                "text": r[1],
                "severity": r[2],
                "session_id": r[3] if len(r) > 3 else "default",
                "timestamp": r[4] if len(r) > 4 else None,
            }
            for r in res
        ]

    def list_all_tenant_findings(self, limit: int = 25) -> List[Dict[str, Any]]:
        """
        Lists all episodic findings recorded in this tenant's graph,
        enforcing zero-leak multi-tenant graph isolation.
        """
        graph = db_pool.get_tenant_graph(self.tenant_id)
        cypher = """
        MATCH (f:Finding)-[:ABOUT]->(h:Host)
        RETURN f.id, f.text, f.severity, h.id, h.name, f.at
        ORDER BY f.at DESC
        LIMIT $limit
        """
        res = graph.ro_query(cypher, {"limit": limit}).result_set
        return [
            {
                "finding_id": r[0],
                "text": r[1],
                "severity": r[2],
                "host_id": r[3],
                "host_name": r[4],
                "timestamp": r[5],
            }
            for r in res
        ]
