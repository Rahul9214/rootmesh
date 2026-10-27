"""
RootMesh — Guarded Incident Response Router
Exposes the 8-stage lifecycle endpoints:
Incident → Investigation → Graph Evidence → Risk Assessment → Proposed Action → Authorized Review → Execution → Verification → Audit
And Track 3 Company Brain organizational traversal endpoints.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.incident.models import (
    ActionProposal,
    CompanyBrainContext,
    ExecuteActionRequest,
    ExecutionAuditResponse,
    IncidentInvestigationReport,
    IncidentInvestigationRequest,
    IncidentSummaryResponse,
    ProposeActionRequest,
    ReviewActionRequest,
)
from app.incident.service import incident_service
from app.security.auth import (
    SecurityPrincipal,
    enforce_tenant_context,
    get_current_principal,
    require_permission,
)
from app.agents.memory import MemoryAgent

logger = logging.getLogger("RootMesh-IncidentRouter")
router = APIRouter(prefix="/api/v1/incident", tags=["Guarded Incident Response"])


@router.post("/investigate", response_model=IncidentInvestigationReport)
async def investigate_threat(
    req: IncidentInvestigationRequest,
    principal: SecurityPrincipal = Depends(require_permission("threat:read")),
):
    """
    Track 1, 2, 3: Full Autonomous Investigation.
    Executes multi-hop traversal, blast-radius UDF, MaxFlow egress risk, shortest path to databases,
    resolves Company Brain ownership, and persists episodic finding and incident graph in FalkorDB.
    """
    return incident_service.investigate_incident(principal=principal, req=req)


@router.post("/propose", response_model=ActionProposal)
async def propose_containment(
    req: ProposeActionRequest,
    principal: SecurityPrincipal = Depends(require_permission("containment:propose")),
):
    """
    Stage 1-5: Investigates target host in FalkorDB, aggregates graph attack paths and egress risk,
    and creates a guarded ActionProposal pending review.
    """
    return incident_service.propose_action(principal=principal, req=req)


@router.post("/review", response_model=ActionProposal)
async def review_containment(
    req: ReviewActionRequest,
    principal: SecurityPrincipal = Depends(require_permission("containment:approve")),
):
    """
    Stage 6: Authorized Review. Requires 'containment:approve' permission.
    Rejections fail closed. Expired approvals fail closed.
    """
    return incident_service.review_action(principal=principal, req=req)


@router.post("/execute", response_model=ExecutionAuditResponse)
async def execute_containment(
    req: ExecuteActionRequest,
    principal: SecurityPrincipal = Depends(require_permission("containment:execute")),
):
    """
    Stage 7 & 8: Execution, Verification, Re-Analysis & Audit.
    Applies graph-level simulated containment, verifies in FalkorDB, calculates before/after differences,
    and records immutable procedural memory. Guarantees replay attack prevention through durable idempotency keys.
    """
    return incident_service.execute_action(principal=principal, req=req)


@router.get("/proposal/{action_id}", response_model=ActionProposal)
async def get_proposal_status(
    action_id: str,
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Inspect status, evidence, and review trail of a specific action proposal."""
    proposal = incident_service.get_proposal(action_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action proposal '{action_id}' not found.",
        )
    enforce_tenant_context(proposal.tenant_id, principal)
    return proposal


@router.get("/company-brain/{tenant_id}/{host_id}", response_model=CompanyBrainContext)
async def get_company_brain(
    tenant_id: str,
    host_id: str,
    principal: SecurityPrincipal = Depends(require_permission("threat:read")),
):
    """
    Track 3 Company Brain: Traverses organizational ownership:
    Compromised host → affected service → owning team → on-call person → relevant runbook / change provenance.
    """
    enforce_tenant_context(tenant_id, principal)
    return incident_service.resolve_company_brain(tenant_id=tenant_id, host_id=host_id)


@router.get("/procedural-memory/{tenant_id}/{host_id}")
async def get_procedural_memory(
    tenant_id: str,
    host_id: str,
    principal: SecurityPrincipal = Depends(require_permission("memory:read")),
):
    """Recalls historical procedural mitigation actions taken on a host (Track 2)."""
    enforce_tenant_context(tenant_id, principal)
    agent = MemoryAgent(tenant_id=tenant_id)
    return agent.recall_procedural_memory(host_id=host_id)


@router.get("/{tenant_id}", response_model=List[IncidentSummaryResponse])
async def list_incidents_for_tenant(
    tenant_id: str,
    limit: int = 5,
    status: Optional[str] = None,
    principal: SecurityPrincipal = Depends(require_permission("threat:read")),
):
    """
    List persisted incidents for a tenant from FalkorDB.
    Guarded by permission checks, bounded retrieval, and strict tenant isolation.
    """
    enforce_tenant_context(tenant_id, principal)
    return incident_service.list_incidents(tenant_id=tenant_id, limit=limit, status=status)


@router.get("/{tenant_id}/{incident_id}")
async def get_incident_details(
    tenant_id: str,
    incident_id: str,
    principal: SecurityPrincipal = Depends(require_permission("threat:read")),
):
    """Recalls complete durable incident provenance, findings, and audit history from FalkorDB."""
    enforce_tenant_context(tenant_id, principal)
    return incident_service.get_incident(tenant_id=tenant_id, incident_id=incident_id)
