"""
RootMesh — Incident Response & Guarded Approval Domain Models
Implements traceable lifecycle states:
Incident → Investigation → Graph Evidence → Risk Assessment → Proposed Action → Authorized Review → Execution → Verification → Audit
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ActionState(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ProposeActionRequest(BaseModel):
    incident_id: str = Field(..., description="Unique incident identifier")
    target_host_id: str = Field(..., description="Target host to isolate/contain")
    action_type: str = Field("CONTAIN_HOST_SIMULATION", description="Type of incident response action")
    tenant_id: str = Field("sec_ops_tenant_alpha", description="Tenant workspace ID")
    justification: str = Field(..., description="Operational justification based on graph evidence")


class ReviewActionRequest(BaseModel):
    action_id: str = Field(..., description="Action proposal ID")
    decision: str = Field(..., description="APPROVE or REJECT")
    comment: str = Field("Authorized review decision", description="Reviewer rationale and notes")


class ExecuteActionRequest(BaseModel):
    action_id: str = Field(..., description="Action proposal ID to execute")
    idempotency_key: str = Field(..., description="Unique idempotency key to prevent replay attacks")


class ActionProposal(BaseModel):
    action_id: str
    incident_id: str
    tenant_id: str
    target_host_id: str
    target_host_name: str
    action_type: str
    proposer_principal: str
    justification: str
    evidence: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    status: ActionState
    created_at: float
    expires_at: float
    reviewed_by: Optional[str] = None
    review_comment: Optional[str] = None
    reviewed_at: Optional[float] = None
    executed_at: Optional[float] = None
    execution_result: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None


class ExecutionAuditResponse(BaseModel):
    action_id: str
    incident_id: str
    tenant_id: str
    target_host_id: str
    status: str
    containment_type: str
    enforcement_note: str
    verification: str
    executed_by: str
    idempotency_key: str
    idempotent_replay: bool
    audit_id: str
    execution_time_ms: float
