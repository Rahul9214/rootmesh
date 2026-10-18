"""
RootMesh — Triage Agent (Track 1 Connected Data Actions)
Autonomous threat reasoning agent that resolves host entities,
executes multi-hop Cypher attack path traversals (*1..N),
and runs FalkorDB Monte Carlo blast-radius simulations.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from app.db.falkor_client import db_pool
from app.db import queries

logger = logging.getLogger("RootMesh-TriageAgent")


class TriageAgent:
    """Performs graph-native threat triage on a patient-zero host."""

    def __init__(self, tenant_id: str = "sec_ops_tenant_alpha") -> None:
        self.tenant_id = tenant_id

    def triage_host(self, host_id: str, max_hops: int = 4) -> Dict[str, Any]:
        """
        Execute complete triage:
        1. Resolve host metadata & CVE vulnerabilities.
        2. Traverse multi-hop attack propagation paths (*1..max_hops).
        3. Execute Monte Carlo blast radius simulation UDF.
        """
        t0 = time.perf_counter()
        graph = db_pool.get_tenant_graph(self.tenant_id)

        # 1. Resolve host info & CVEs
        host_query = """
        MATCH (h:Host {id: $hid})
        OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(c:CVE)
        RETURN h.id, h.name, h.ip, h.edr, h.smb_signing, h.firewall,
               collect(c.id) AS cves
        """
        host_res = graph.ro_query(host_query, {"hid": host_id}).result_set
        if not host_res or not host_res[0][0]:
            return {
                "status": "NOT_FOUND",
                "host_id": host_id,
                "error": f"Host '{host_id}' not found in graph '{self.tenant_id}'.",
            }

        h = host_res[0]
        host_meta = {
            "id": h[0],
            "name": h[1],
            "ip": h[2],
            "edr": bool(h[3]),
            "smb_signing": bool(h[4]),
            "firewall": bool(h[5]),
            "cves": h[6] if h[6] else [],
        }

        # 2. Multi-hop path traversal
        cypher_traversal = queries.MULTI_HOP_TRAVERSAL.replace("{max_hops}", str(max_hops))
        paths_raw = graph.ro_query(cypher_traversal, {"patient_zero_id": host_id}).result_set

        attack_paths = [
            {
                "target_name": row[0] or "Unknown",
                "target_ip": row[1] or "N/A",
                "hops": row[2],
                "path": row[3] or [],
            }
            for row in paths_raw
        ]

        # 3. Monte Carlo Blast Radius UDF
        blast_results: Dict[str, int] = {}
        try:
            udf_cypher = "RETURN blast_radius_lib.blast_radius($pz, 100) AS result"
            res = graph.ro_query(udf_cypher, {"pz": host_id}).result_set
            if res and res[0][0]:
                raw = res[0][0]
                blast_results = json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            logger.debug("Monte Carlo UDF fallback: %s", e)

        exec_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "status": "TRIAGED",
            "host": host_meta,
            "target_count": len(attack_paths),
            "attack_paths": attack_paths,
            "blast_radius": blast_results,
            "execution_time_ms": exec_ms,
        }
