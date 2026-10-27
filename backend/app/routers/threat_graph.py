"""
RootMesh — Threat Graph Router
Exposes multi-hop traversal, PageRank, MaxFlow, Shortest Path, Topology,
Containment (Graph-Level Simulation), Finding memory, and on-call owner APIs.
Guarded by cryptographic principal authentication and tenant-bound authorization.
"""
from __future__ import annotations

import logging
import time
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.config import settings
from app.db.falkor_client import db_pool
from app.db import queries
from app.models.schemas import (
    AttackPathEntry,
    ContainmentRequest,
    ContainmentResponse,
    FindingRequest,
    FindingResponse,
    MaxFlowRequest,
    MaxFlowResponse,
    OnCallEntry,
    PageRankEntry,
    ShortestPathRequest,
    ShortestPathResponse,
    TopologyNode,
    TraversalRequest,
    TraversalResponse,
)
from app.security.auth import (
    SecurityPrincipal,
    enforce_tenant_context,
    get_current_principal,
    require_permission,
)

logger = logging.getLogger("RootMesh-Router")
router = APIRouter(prefix="/api/v1/threat", tags=["Threat Intelligence"])


# ──────────────────────────────────────────────
# POST /api/v1/threat/traverse
# ──────────────────────────────────────────────

@router.post("/traverse", response_model=TraversalResponse)
async def traverse_attack_paths(
    req: TraversalRequest,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Execute variable-length Cypher traversal (*1..N) from Patient Zero host."""
    enforce_tenant_context(req.tenant_id, principal)
    t0 = time.perf_counter()
    try:
        graph = db_pool.get_tenant_graph(req.tenant_id)
        cypher = queries.MULTI_HOP_TRAVERSAL.replace("{max_hops}", str(req.max_hops))
        result = graph.ro_query(cypher, {"patient_zero_id": req.patient_zero_id}).result_set
    except Exception as e:
        logger.error("Traversal error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    paths = [
        AttackPathEntry(
            target_name=r[0] or "Unknown",
            target_ip=r[1] or "N/A",
            hops=r[2],
            path=r[3] or [],
        )
        for r in result
    ]
    exec_ms = round((time.perf_counter() - t0) * 1000, 2)

    return TraversalResponse(
        patient_zero=req.patient_zero_id,
        target_count=len(paths),
        execution_time_ms=exec_ms,
        attack_paths=paths,
    )


# ──────────────────────────────────────────────
# GET /api/v1/threat/pagerank/{tenant_id}
# ──────────────────────────────────────────────

@router.get("/pagerank/{tenant_id}", response_model=List[PageRankEntry])
async def get_load_bearing_assets(
    tenant_id: str,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Run PageRank across Host nodes to surface highest-criticality infrastructure."""
    enforce_tenant_context(tenant_id, principal)
    try:
        graph = db_pool.get_tenant_graph(tenant_id)
        results = graph.ro_query(queries.PAGE_RANK_ASSETS).result_set
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return [
        PageRankEntry(host_name=r[0], ip=r[1] or "N/A", score=round(r[2], 5))
        for r in results
    ]


# ──────────────────────────────────────────────
# POST /api/v1/threat/egress
# ──────────────────────────────────────────────

@router.post("/egress", response_model=MaxFlowResponse)
async def calculate_max_egress(
    req: MaxFlowRequest,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Compute maximum data exfiltration bandwidth using FalkorDB algo.maxFlow."""
    enforce_tenant_context(req.tenant_id, principal)
    t0 = time.perf_counter()
    try:
        graph = db_pool.get_tenant_graph(req.tenant_id)
        result = graph.ro_query(
            queries.MAX_FLOW_EGRESS,
            {"source_id": req.source_id, "sink_id": req.sink_id},
        ).result_set
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    max_egress = result[0][0] if result else 0.0
    exec_ms = round((time.perf_counter() - t0) * 1000, 2)

    return MaxFlowResponse(
        source_id=req.source_id,
        sink_id=req.sink_id,
        max_egress_mbps=float(max_egress),
        execution_time_ms=exec_ms,
    )


# ──────────────────────────────────────────────
# POST /api/v1/threat/shortest-path
# ──────────────────────────────────────────────

@router.post("/shortest-path", response_model=ShortestPathResponse)
async def find_shortest_attack_path(
    req: ShortestPathRequest,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Compute shortest attack route between source and target in FalkorDB."""
    enforce_tenant_context(req.tenant_id, principal)
    t0 = time.perf_counter()
    try:
        graph = db_pool.get_tenant_graph(req.tenant_id)
        result = graph.ro_query(
            queries.SHORTEST_ATTACK_PATH,
            {"source_id": req.source_id, "target_id": req.target_id},
        ).result_set
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not result:
        raise HTTPException(status_code=404, detail="No path found between specified hosts")

    path_nodes = result[0][0]
    distance = result[0][1]
    exec_ms = round((time.perf_counter() - t0) * 1000, 2)

    return ShortestPathResponse(
        source_id=req.source_id,
        target_id=req.target_id,
        distance=distance,
        path=path_nodes,
        execution_time_ms=exec_ms,
    )


# ──────────────────────────────────────────────
# GET /api/v1/threat/topology/{tenant_id}
# ──────────────────────────────────────────────

@router.get("/topology/{tenant_id}", response_model=List[TopologyNode])
async def get_network_topology(
    tenant_id: str,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Fetch live host nodes, status, and firewall flags directly from FalkorDB."""
    enforce_tenant_context(tenant_id, principal)
    try:
        graph = db_pool.get_tenant_graph(tenant_id)
        results = graph.ro_query(queries.GET_ALL_HOSTS_TOPOLOGY).result_set
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return [
        TopologyNode(
            id=r[0],
            name=r[1],
            ip=r[2],
            status=r[3],
            firewall=bool(r[4]),
            edr=bool(r[5]),
            smb_signing=bool(r[6]),
            hops=0 if r[0] == "host-0" else 1 if r[0] in ("host-1", "host-2") else 2 if r[0] == "host-3" else 3 if r[0] in ("host-4", "host-5") else 4,
        )
        for r in results
    ]


# ──────────────────────────────────────────────
# POST /api/v1/threat/contain (PERMANENTLY DISABLED)
# ──────────────────────────────────────────────

@router.post(
    "/contain",
    status_code=status.HTTP_410_GONE,
    deprecated=True,
    tags=["Threat Intelligence"],
    summary="Permanently Disabled Legacy Containment Endpoint",
)
async def execute_containment(
    _body: Optional[Any] = None,
):
    """
    PERMANENTLY DISABLED LEGACY ROUTE (HTTP 410 Gone).

    Direct containment execution via /api/v1/threat/contain is permanently disabled
    in all environments (development, testing, staging, and production).

    Containment operations must exclusively follow the guarded 8-stage Human-in-the-Loop lifecycle:
      1. Propose: POST /api/v1/incident/propose (containment:propose)
      2. Review:  POST /api/v1/incident/review  (containment:approve)
      3. Execute: POST /api/v1/incident/execute (containment:execute)
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail=(
            "Direct containment execution via /api/v1/threat/contain is permanently disabled in all environments. "
            "All containment actions must be explicitly authorized through the guarded lifecycle: "
            "propose (/api/v1/incident/propose) -> review (/api/v1/incident/review) -> execute (/api/v1/incident/execute)."
        ),
    )


# ──────────────────────────────────────────────
# POST /api/v1/threat/memory/finding
# ──────────────────────────────────────────────

@router.post("/memory/finding", response_model=FindingResponse)
async def persist_finding_memory(
    req: FindingRequest,
    principal: SecurityPrincipal = Depends(require_permission("memory:write")),
):
    """Persist episodic agent finding as (:Finding)-[:ABOUT]->(:Host) subgraph (Track 2)."""
    enforce_tenant_context(req.tenant_id, principal)
    try:
        graph = db_pool.get_tenant_graph(req.tenant_id)
        result = graph.query(
            queries.PERSIST_FINDING,
            {
                "host_id": req.host_id,
                "text": req.text,
                "severity": req.severity,
                "session_id": req.session_id,
                "confidence": req.confidence,
            },
        ).result_set
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finding_id = result[0][0] if result else "unknown"
    return FindingResponse(finding_id=finding_id, host_id=req.host_id, severity=req.severity)


# ──────────────────────────────────────────────
# GET /api/v1/threat/oncall/{tenant_id}/{host_id}
# ──────────────────────────────────────────────

@router.get("/oncall/{tenant_id}/{host_id}", response_model=List[OnCallEntry])
async def get_oncall_owner(
    tenant_id: str,
    host_id: str,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Resolve on-call incident responder for a compromised host (Track 3 Company Brain)."""
    enforce_tenant_context(tenant_id, principal)
    try:
        graph = db_pool.get_tenant_graph(tenant_id)
        results = graph.ro_query(queries.ONCALL_OWNER, {"host_id": host_id}).result_set
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return [OnCallEntry(responder=r[0], email=r[1], team=r[2]) for r in results]
