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


class CompanyBrainContext(BaseModel):
    """Track 3: Connected Organizational Context for an Incident Entity."""
    host_id: str
    host_name: str
    host_ip: str
    host_status: str
    firewall: bool
    service_id: Optional[str] = None
    service_name: Optional[str] = None
    service_tier: Optional[str] = None
    repo: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    slack_channel: Optional[str] = None
    responder_id: Optional[str] = None
    oncall_name: Optional[str] = None
    oncall_email: Optional[str] = None
    oncall_role: Optional[str] = None
    oncall_schedule: Optional[str] = None
    runbook_id: Optional[str] = None
    runbook_title: Optional[str] = None
    runbook_url: Optional[str] = None
    runbook_sla_minutes: Optional[int] = None
    commit_sha: Optional[str] = None
    commit_author: Optional[str] = None
    commit_message: Optional[str] = None
    commit_timestamp: Optional[str] = None
    data_classification: str = Field(
        "SYNTHETIC_DEMONSTRATION",
        description="Explicit classification: synthetic demonstration graph data; not verified live external integration.",
    )
    integration_notice: str = Field(
        "DEMONSTRATION ONLY: Personnel, runbook links, and commit SHAs are simulated knowledge graph entities in FalkorDB.",
        description="Explicit notice regarding external integration status.",
    )


class BeforeAfterEvidence(BaseModel):
    """Track 1 & 2: Factual Before/After Containment Graph Differences."""
    target_host_id: str
    target_host_name: str
    before_status: str
    before_firewall: bool
    before_egress_mbps: float
    before_active_paths: int
    after_status: str
    after_firewall: bool
    after_egress_mbps: float
    after_active_paths: int
    paths_severed: int
    egress_reduction_mbps: float
    containment_type: str = "GRAPH_TOPOLOGY_SIMULATION"
    enforcement_note: str = (
        "Graph-level isolation verified in FalkorDB. "
        "Physical hardware firewall rule enforcement requires authorized appliance connector."
    )


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
    before_after: Optional[BeforeAfterEvidence] = None
    company_brain: Optional[CompanyBrainContext] = None


class IncidentInvestigationRequest(BaseModel):
    patient_zero_id: str = Field("host-0", description="Patient Zero Host ID to investigate")
    tenant_id: str = Field("sec_ops_tenant_alpha", description="Tenant ID")
    incident_id: Optional[str] = Field(None, description="Optional incident ID (generated if not provided)")
    title: Optional[str] = Field(None, description="Incident title or description")


class IncidentInvestigationReport(BaseModel):
    """Track 1, 2 & 3: Full Autonomous Investigation Report."""
    incident_id: str
    tenant_id: str
    patient_zero_id: str
    patient_zero_name: str
    title: str
    status: str
    created_at: float
    company_brain: CompanyBrainContext
    attack_paths: List[Dict[str, Any]]
    target_count: int
    shortest_path_to_db: Optional[Dict[str, Any]] = None
    pagerank_critical_assets: List[Dict[str, Any]]
    egress_risk_mbps: float
    blast_radius_simulation: Dict[str, Any]
    episodic_findings: List[Dict[str, Any]]
    procedural_memories: List[Dict[str, Any]]
    recommended_containment: Dict[str, Any]
    investigation_time_ms: float
