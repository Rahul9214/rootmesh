"""
RootMesh — Strict Pydantic V2 Response Models
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Traversal
# ──────────────────────────────────────────────

class AttackPathEntry(BaseModel):
    target_name: str
    target_ip: str
    hops: int
    path: List[str]


class TraversalRequest(BaseModel):
    tenant_id: str = Field(default="sec_ops_tenant_alpha")
    patient_zero_id: str = Field(..., examples=["host-0"])
    max_hops: int = Field(default=4, ge=1, le=10)


class TraversalResponse(BaseModel):
    patient_zero: str
    target_count: int
    execution_time_ms: float
    attack_paths: List[AttackPathEntry]


# ──────────────────────────────────────────────
# PageRank
# ──────────────────────────────────────────────

class PageRankEntry(BaseModel):
    host_name: str
    ip: str
    score: float


# ──────────────────────────────────────────────
# MaxFlow & Shortest Path
# ──────────────────────────────────────────────

class MaxFlowRequest(BaseModel):
    tenant_id: str = Field(default="sec_ops_tenant_alpha")
    source_id: str = Field(..., examples=["host-0"])
    sink_id: str = Field(..., examples=["host-7"])


class MaxFlowResponse(BaseModel):
    source_id: str
    sink_id: str
    max_egress_mbps: float
    execution_time_ms: float


class ShortestPathRequest(BaseModel):
    tenant_id: str = Field(default="sec_ops_tenant_alpha")
    source_id: str = Field(..., examples=["host-0"])
    target_id: str = Field(..., examples=["host-7"])


class ShortestPathResponse(BaseModel):
    source_id: str
    target_id: str
    distance: int
    path: List[str]
    execution_time_ms: float


# ──────────────────────────────────────────────
# Topology & Containment (Distinguishing Graph Sim)
# ──────────────────────────────────────────────

class TopologyNode(BaseModel):
    id: str
    name: str
    ip: str
    status: str
    firewall: bool
    edr: bool
    smb_signing: bool
    hops: int = 0


class ContainmentRequest(BaseModel):
    tenant_id: str = Field(default="sec_ops_tenant_alpha")
    host_id: str = Field(..., examples=["host-0"])


class ContainmentResponse(BaseModel):
    status: str
    host_id: str
    host_name: str
    firewall_active: bool
    containment_type: str = "GRAPH_TOPOLOGY_SIMULATION"
    enforcement_note: str = (
        "Graph-level isolation verified in FalkorDB. "
        "Physical hardware firewall rule enforcement requires authorized appliance connector."
    )
    execution_time_ms: float


# ──────────────────────────────────────────────
# Finding Memory (Track 2)
# ──────────────────────────────────────────────

class FindingRequest(BaseModel):
    tenant_id: str = Field(default="sec_ops_tenant_alpha")
    host_id: str
    text: str
    severity: str = Field(default="HIGH", pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    session_id: str = Field(default="default-session")
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)


class FindingResponse(BaseModel):
    finding_id: str
    host_id: str
    severity: str


# ──────────────────────────────────────────────
# On-Call Owner (Track 3)
# ──────────────────────────────────────────────

class OnCallEntry(BaseModel):
    responder: str
    email: str
    team: str


# ──────────────────────────────────────────────
# WebSocket broadcast payload
# ──────────────────────────────────────────────

class WsAttackEvent(BaseModel):
    event: str
    patient_zero: str
    impacted_assets: int
    execution_ms: float
