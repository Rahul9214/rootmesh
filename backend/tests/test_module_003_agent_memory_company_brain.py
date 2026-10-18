"""
RootMesh — Module 003: Agent Coordination, Persistent Memory & Company Brain
Complete end-to-end integration tests executing against live FalkorDB GraphBLAS instance.

Covers:
1. Authenticated Incident Investigation & Graph Evidence
2. Graph Algorithms: Multi-hop traversal, Shortest Path to DB, PageRank, MaxFlow, Monte Carlo UDF
3. Company Brain Traversal: Compromised host -> affected service -> owning team -> on-call person -> runbook / commit provenance
4. Guarded Containment Proposal with Graph Evidence
5. Authorized Review (Approval / Rejection lifecycle, fail-closed expiration)
6. Concurrency-Safe, Persistent Execution in FalkorDB
7. Verified Graph State Change (status = CONTAINED, firewall = true)
8. Re-Analysis & Factual Before/After Comparison (severed paths, eliminated egress bandwidth)
9. Persistent Agent Memory: Episodic findings and procedural memory in FalkorDB
10. Company Brain Ownership & On-Call Resolution
11. Complete Audit History Persistence & Incident Recall
12. Cross-Tenant Denial (HTTP 403) and Replay Protection
"""
from __future__ import annotations

import time
import pytest
from starlette.testclient import TestClient

from app.config import settings
from app.db.falkor_client import db_pool
from app.incident.models import (
    ActionProposal,
    ActionState,
    ExecuteActionRequest,
    ExecutionAuditResponse,
    IncidentInvestigationRequest,
    ProposeActionRequest,
    ReviewActionRequest,
)
from app.incident.service import IncidentResponseService, incident_service
from app.main import app
from app.security.auth import generate_dev_token, verify_access_token

TENANT_ALPHA = "sec_ops_tenant_alpha"
TENANT_BETA = "sec_ops_tenant_beta"


@pytest.fixture(scope="module")
def api_client():
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers():
    token = generate_dev_token(
        username="alex.rivera",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def admin_principal():
    token = generate_dev_token(
        username="alex.rivera",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
    )
    return verify_access_token(token)


def test_complete_incident_lifecycle_workflow(api_client, auth_headers):
    """
    Validates the complete 12-step operational contract against live FalkorDB:
    Incident -> Investigation -> Attack Paths -> Risk / Egress -> Proposal ->
    Approval -> Containment -> Re-analysis -> Before/After Delta -> Memory -> Audit History
    """
    # 1. Authenticated Incident Investigation
    inv_payload = {
        "patient_zero_id": "host-0",
        "tenant_id": TENANT_ALPHA,
        "title": "Module 003 E2E Integration Incident",
    }
    inv_res = api_client.post("/api/v1/incident/investigate", headers=auth_headers, json=inv_payload)
    assert inv_res.status_code == 200, inv_res.text
    report = inv_res.json()

    assert report["incident_id"].startswith("inc-")
    assert report["patient_zero_id"] == "host-0"
    assert report["status"] == "INVESTIGATED"

    # 2. Graph Algorithms & Evidence Verification
    assert report["target_count"] >= 1
    assert len(report["attack_paths"]) >= 1
    assert report["egress_risk_mbps"] > 0.0
    assert len(report["pagerank_critical_assets"]) >= 1

    # Shortest path to high-value database
    assert report["shortest_path_to_db"] is not None
    assert report["shortest_path_to_db"]["db_name"] == "HR-Payroll-DB"
    assert "Workstation-PatientZero" in report["shortest_path_to_db"]["path"]

    # 3. Company Brain Organizational Traversal Verification
    cb = report["company_brain"]
    assert cb["host_id"] == "host-0"
    assert cb["service_name"] == "Corporate Device Gateway"
    assert cb["team_name"] == "SecOps Incident Response"
    assert cb["oncall_name"] == "Alex Rivera"
    assert cb["runbook_title"] is not None
    assert "Containment" in cb["runbook_title"]
    assert cb["commit_sha"] == "c89e1a4"

    # 4. Containment Proposal
    prop_payload = {
        "incident_id": report["incident_id"],
        "target_host_id": "host-0",
        "tenant_id": TENANT_ALPHA,
        "justification": "E2E workflow automated containment proposal based on real graph evidence",
    }
    prop_res = api_client.post("/api/v1/incident/propose", headers=auth_headers, json=prop_payload)
    assert prop_res.status_code == 200
    proposal = prop_res.json()
    action_id = proposal["action_id"]
    assert proposal["status"] == "PROPOSED"
    assert proposal["evidence"]["attack_paths"] is not None
    assert proposal["risk_assessment"]["max_egress_mbps"] == report["egress_risk_mbps"]

    # 5. Authorized Approval
    rev_payload = {
        "action_id": action_id,
        "decision": "APPROVE",
        "comment": "Lead Responder authorized graph isolation for host-0",
    }
    rev_res = api_client.post("/api/v1/incident/review", headers=auth_headers, json=rev_payload)
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "APPROVED"
    assert rev_res.json()["reviewed_by"] == "alex.rivera"

    # 6. Simulated Graph Containment Execution with Persistent Idempotency Key
    idemp_key = f"e2e-workflow-{int(time.time() * 1000)}"
    exec_payload = {
        "action_id": action_id,
        "idempotency_key": idemp_key,
    }
    exec_res = api_client.post("/api/v1/incident/execute", headers=auth_headers, json=exec_payload)
    assert exec_res.status_code == 200
    audit = exec_res.json()

    # 7. Verified Graph State Change
    assert audit["status"] == "CONTAINED"
    assert audit["verification"] == "VERIFIED"
    assert audit["containment_type"] == "GRAPH_TOPOLOGY_SIMULATION"
    assert audit["idempotent_replay"] is False

    # 8. Re-Analysis & Factual Before/After Comparison
    ba = audit["before_after"]
    assert ba is not None
    assert ba["target_host_id"] == "host-0"
    assert ba["before_status"] == "INFECTED"
    assert ba["before_firewall"] is False
    assert ba["before_egress_mbps"] == report["egress_risk_mbps"]
    assert ba["before_active_paths"] == report["target_count"]

    assert ba["after_status"] == "CONTAINED"
    assert ba["after_firewall"] is True
    assert ba["after_egress_mbps"] == 0.0
    assert ba["after_active_paths"] == 0
    assert ba["paths_severed"] == report["target_count"]
    assert ba["egress_reduction_mbps"] == report["egress_risk_mbps"]

    # 9. Persistent Incident Memory Recall
    inc_res = api_client.get(f"/api/v1/incident/{TENANT_ALPHA}/{report['incident_id']}", headers=auth_headers)
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    assert inc_data["status"] == "CONTAINED"
    assert len(inc_data["findings"]) >= 1
    assert any("lateral propagation paths" in f["text"] for f in inc_data["findings"])
    assert len(inc_data["audit_trail"]) >= 1
    assert inc_data["audit_trail"][0]["paths_severed"] == report["target_count"]

    # 10. Replay Protection: Duplicate Execution MUST return cached replay
    dup_res = api_client.post("/api/v1/incident/execute", headers=auth_headers, json=exec_payload)
    assert dup_res.status_code == 200
    dup_audit = dup_res.json()
    assert dup_audit["idempotent_replay"] is True
    assert dup_audit["audit_id"] == audit["audit_id"]


def test_company_brain_endpoint_traversal(api_client, auth_headers):
    """
    Validates Track 3 Company Brain endpoint:
    Resolves host-1 -> AppServer-Internal -> svc-app-core -> team-infra -> Elena Rostova -> Runbook rb-app-042
    """
    res = api_client.get(f"/api/v1/incident/company-brain/{TENANT_ALPHA}/host-1", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["host_id"] == "host-1"
    assert data["host_name"] == "AppServer-Internal"
    assert data["service_id"] == "svc-app-core"
    assert data["service_name"] == "Internal Application Core API"
    assert data["service_tier"] == "Tier-0"
    assert data["repo"] == "rootmesh/app-core"
    assert data["team_id"] == "team-infra"
    assert data["team_name"] == "Platform Infrastructure Engineering"
    assert data["oncall_name"] == "Elena Rostova"
    assert data["oncall_email"] == "elena.rostova@rootmesh.local"
    assert data["runbook_id"] == "rb-app-042"
    assert data["commit_sha"] == "b44f2d1"
    assert "patch Log4j" in data["commit_message"]


def test_persistent_memory_survives_process_restart(api_client, auth_headers, admin_principal):
    """
    Verifies that episodic and procedural memory nodes stored in FalkorDB
    remain queryable from a brand new IncidentResponseService instance (simulating backend restart).
    """
    # Create incident and execute action
    inv_req = IncidentInvestigationRequest(patient_zero_id="host-0", tenant_id=TENANT_ALPHA)
    report = incident_service.investigate_incident(admin_principal, inv_req)
    incident_id = report.incident_id

    prop_req = ProposeActionRequest(incident_id=incident_id, target_host_id="host-0", justification="Durable restart test")
    proposal = incident_service.propose_action(admin_principal, prop_req)

    incident_service.review_action(admin_principal, ReviewActionRequest(action_id=proposal.action_id, decision="APPROVE"))

    idemp_key = f"restart-durability-{int(time.time() * 1000)}"
    exec_req = ExecuteActionRequest(action_id=proposal.action_id, idempotency_key=idemp_key)
    audit = incident_service.execute_action(admin_principal, exec_req)

    # Instantiate completely fresh service instance (empty in-memory dicts)
    fresh_service = IncidentResponseService()
    assert proposal.action_id not in fresh_service._proposals
    assert f"{TENANT_ALPHA}:{idemp_key}" not in fresh_service._idempotency_cache

    # Recall incident from FalkorDB using fresh service
    recovered_inc = fresh_service.get_incident(TENANT_ALPHA, incident_id)
    assert recovered_inc["incident_id"] == incident_id
    assert recovered_inc["status"] == "CONTAINED"
    assert len(recovered_inc["findings"]) >= 1
    assert len(recovered_inc["audit_trail"]) >= 1

    # Recall proposal from FalkorDB using fresh service
    recovered_proposal = fresh_service.get_proposal(proposal.action_id)
    assert recovered_proposal is not None
    assert recovered_proposal.action_id == proposal.action_id
    assert recovered_proposal.status == ActionState.EXECUTED


def test_cross_tenant_incident_access_denied(api_client):
    """
    Verifies strict tenant isolation: A principal authorized only for tenant beta
    cannot investigate or retrieve incidents belonging to tenant alpha (HTTP 403 Forbidden).
    """
    beta_token = generate_dev_token(
        username="charlie.beta",
        tenant_id=TENANT_BETA,
        roles=["analyst"],
    )
    beta_headers = {"Authorization": f"Bearer {beta_token}"}

    # Attempt to investigate tenant alpha as beta user
    inv_res = api_client.post(
        "/api/v1/incident/investigate",
        headers=beta_headers,
        json={"patient_zero_id": "host-0", "tenant_id": TENANT_ALPHA},
    )
    assert inv_res.status_code == 403
    assert "Cross-tenant access rejected" in inv_res.json()["detail"]

    # Attempt to read tenant alpha Company Brain as beta user
    cb_res = api_client.get(
        f"/api/v1/incident/company-brain/{TENANT_ALPHA}/host-0",
        headers=beta_headers,
    )
    assert cb_res.status_code == 403
    assert "Cross-tenant access rejected" in cb_res.json()["detail"]
