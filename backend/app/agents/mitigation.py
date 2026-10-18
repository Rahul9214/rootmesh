"""
RootMesh — Mitigation Agent (Track 1 & Track 3 Company Brain)
Calculates maximum network egress via FalkorDB GraphBLAS algo.maxFlow,
resolves on-call incident responders and engineering teams,
and executes graph-level containment simulations.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from app.db.falkor_client import db_pool
from app.db import queries

logger = logging.getLogger("RootMesh-MitigationAgent")


class MitigationAgent:
    """Computes egress risk, resolves responders, and executes containment."""

    def __init__(self, tenant_id: str = "sec_ops_tenant_alpha") -> None:
        self.tenant_id = tenant_id

    def assess_egress_risk(self, source_id: str, sink_id: str = "host-7") -> Dict[str, Any]:
        """
        Calculates maximum exfiltration bandwidth from source to egress firewall
        using FalkorDB GraphBLAS algo.maxFlow.
        """
        t0 = time.perf_counter()
        graph = db_pool.get_tenant_graph(self.tenant_id)

        try:
            res = graph.ro_query(
                queries.MAX_FLOW_EGRESS,
                {"source_id": source_id, "sink_id": sink_id},
            ).result_set
            max_egress = float(res[0][0]) if res else 0.0
        except Exception as e:
            logger.warning("MaxFlow query error: %s", e)
            max_egress = 0.0

        exec_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "source_id": source_id,
            "sink_id": sink_id,
            "max_egress_mbps": max_egress,
            "execution_time_ms": exec_ms,
        }

    def resolve_incident_responders(self, host_id: str) -> List[Dict[str, str]]:
        """
        Resolves team ownership and active on-call responders for a host
        from the organizational graph model (Track 3 Company Brain).
        """
        graph = db_pool.get_tenant_graph(self.tenant_id)
        results = graph.ro_query(queries.ONCALL_OWNER, {"host_id": host_id}).result_set
        return [
            {"responder": r[0], "email": r[1], "team": r[2]}
            for r in results
        ]

    def execute_containment(self, host_id: str) -> Dict[str, Any]:
        """
        Executes graph-level simulated containment action by activating host firewall
        in FalkorDB to halt lateral movement.

        CRITICAL ARCHITECTURAL DISTINCTION:
        This updates graph topology to reflect containment. Real-world physical firewall
        enforcement requires an authorized hardware appliance integration (e.g. Palo Alto / iptables).
        """
        t0 = time.perf_counter()
        graph = db_pool.get_tenant_graph(self.tenant_id)

        cypher = """
        MATCH (h:Host {id: $hid})
        SET h.firewall = true, h.status = 'CONTAINED'
        RETURN h.id, h.name, h.firewall
        """
        res = graph.query(cypher, {"hid": host_id}).result_set
        exec_ms = round((time.perf_counter() - t0) * 1000, 2)

        if not res:
            return {"status": "FAILED", "error": f"Host '{host_id}' not found in graph."}

        return {
            "status": "CONTAINED",
            "host_id": res[0][0],
            "host_name": res[0][1],
            "firewall_active": True,
            "containment_type": "GRAPH_TOPOLOGY_SIMULATION",
            "enforcement_note": (
                "Graph-level isolation verified in FalkorDB. "
                "Physical hardware firewall rule enforcement requires authorized appliance connector."
            ),
            "execution_time_ms": exec_ms,
        }
