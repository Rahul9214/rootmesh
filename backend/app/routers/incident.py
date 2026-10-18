"""
RootMesh — Guarded Incident Response Router
Exposes the 8-stage lifecycle endpoints:
Incident → Investigation → Graph Evidence → Risk Assessment → Proposed Action → Authorized Review → Execution → Verification → Audit
"""
from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from app.incident.models import (
    ActionProposal,
    ExecuteActionRequest,
    ExecutionAuditResponse,
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
    Stage 7 & 8: Execution, Verification & Audit.
    Applies graph-level simulated containment, verifies in FalkorDB, and records immutable procedural memory.
    Guarantees replay attack prevention through durable idempotency keys.
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
