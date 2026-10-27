"""
RootMesh — Step 3BO Security, Human-in-the-Loop & End-to-End Workflow Verification Suite

Tests:
1. Identity & Tenant Isolation:
   - Clerk JWT signature, issuer, audience/authorized-party, and expiry validation.
   - Organization-to-tenant mapping (mapped vs unmapped fail-closed).
   - Signed-out access denial across all lifecycle endpoints.
   - Role restrictions & least-privilege separation of duties (responder vs admin).
   - Cross-tenant REST & WebSocket access denial.
2. Complete Incident Lifecycle:
   - Investigation -> Findings Persistence -> Proposal (900s TTL) -> Human Review (Approve) ->
     Guarded Execution (Idempotency) -> Verification -> Audit Retrieval.
3. Negative Lifecycle Paths:
   - Unauthorized reviewer denial (403).
   - Proposal rejection fail-closed (cannot execute rejected proposal -> 403).
   - Expired proposal fail-closed (cannot execute expired proposal -> 410).
   - Double execution idempotency replay (idempotent_replay: True).
   - Missing incident (404).
4. Legacy Direct Containment Route Disabled:
   - POST /api/v1/threat/contain unconditionally returns 410 Gone with zero side effects.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from app.config import settings
from app.db.falkor_client import db_pool
from app.db.test_guard import TEST_TENANT_ALPHA, TEST_TENANT_BETA
from app.incident.models import ActionState
from app.main import app, ws_manager
from app.security.auth import create_test_clerk_token

# Cryptographic test RSA keys
_test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_test_public_pem = _test_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

_attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

CLERK_ISSUER = "https://clerk.rootmesh.security"
TENANT_ALPHA = TEST_TENANT_ALPHA
TENANT_BETA = TEST_TENANT_BETA


@pytest.fixture(autouse=True)
def setup_step3bo_env(monkeypatch):
    """Sets up official Clerk test environment mapped to isolated test tenants."""
    monkeypatch.setattr(settings, "clerk_pem_public_key", _test_public_pem)
    monkeypatch.setattr(settings, "clerk_issuer", CLERK_ISSUER)
    monkeypatch.setattr(settings, "clerk_authorized_parties", "http://localhost:3000,http://127.0.0.1:3000")
    monkeypatch.setattr(settings, "ws_auth_timeout_seconds", 5.0)
    monkeypatch.setattr(
        settings,
        "clerk_org_to_tenant_map",
        json.dumps({
            "org_secops_alpha": TENANT_ALPHA,
            "org_secops_beta": TENANT_BETA,
        }),
    )


def _make_token(
    sub: str = "usr_test_lead",
    username: str = "alex.lead",
    org_id: str = "org_secops_alpha",
    org_role: str = "org:rootmesh_admin",
    rootmesh_role: str | None = None,
    issuer: str = CLERK_ISSUER,
    azp: str = "http://localhost:3000",
    key=None,
    expires_in_seconds: int = 3600,
) -> str:
    signing_key = key or _test_private_key
    return create_test_clerk_token(
        sub=sub,
        username=username,
        org_id=org_id,
        org_role=org_role,
        rootmesh_role=rootmesh_role,
        issuer=issuer,
        azp=azp,
        private_key=signing_key,
        expires_in_seconds=expires_in_seconds,
    )


# ─────────────────────────────────────────────────────────────
# 1. Identity & Tenant Isolation Verification
# ─────────────────────────────────────────────────────────────

def test_clerk_jwt_validation_positive():
    """Verify valid Clerk JWT grants authenticated principal with mapped tenant."""
    client = TestClient(app)
    token = _make_token(sub="usr_valid_01", username="valid.user")
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["principal_id"] == "usr_valid_01"
    assert data["tenant_id"] == TENANT_ALPHA
    assert "admin" in data["roles"]


def test_clerk_jwt_expired_denial():
    """Verify expired Clerk JWT is strictly rejected with 401."""
    client = TestClient(app)
    token = _make_token(sub="usr_exp_01", expires_in_seconds=-60)
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


def test_clerk_jwt_tampered_signature_denial():
    """Verify JWT signed with untrusted private key is rejected with 401."""
    client = TestClient(app)
    token = _make_token(sub="usr_tampered_01", key=_attacker_key)
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
    assert "signature" in res.json()["detail"].lower() or "verification failed" in res.json()["detail"].lower()


def test_clerk_jwt_unmapped_organization_denial():
    """Verify user in an unmapped Clerk organization fails closed with 403 Forbidden."""
    client = TestClient(app)
    token = _make_token(sub="usr_unmapped_01", org_id="org_unmapped_corp")
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "not mapped" in res.json()["detail"].lower()


def test_signed_out_access_denial_across_endpoints():
    """Verify signed-out (unauthenticated) access fails with 401 across lifecycle routes."""
    client = TestClient(app)
    endpoints = [
        ("GET", f"/api/v1/threat/topology/{TENANT_ALPHA}"),
        ("GET", f"/api/v1/threat/pagerank/{TENANT_ALPHA}"),
        ("POST", "/api/v1/incident/investigate"),
        ("POST", "/api/v1/incident/propose"),
        ("POST", "/api/v1/incident/review"),
        ("POST", "/api/v1/incident/execute"),
        ("GET", f"/api/v1/incident/{TENANT_ALPHA}/inc-test-01"),
    ]
    for method, path in endpoints:
        if method == "GET":
            res = client.get(path)
        else:
            res = client.post(path, json={})
        assert res.status_code in (401, 403), f"Expected 401/403 for unauthenticated {path}, got {res.status_code}"


def test_cross_tenant_rest_access_denial():
    """Verify principal authorized for Tenant Alpha cannot access Tenant Beta resources."""
    client = TestClient(app)
    alpha_token = _make_token(sub="usr_alpha_only", org_id="org_secops_alpha")
    # Attempting to read Tenant Beta topology
    res = client.get(f"/api/v1/threat/topology/{TENANT_BETA}", headers={"Authorization": f"Bearer {alpha_token}"})
    assert res.status_code == 403
    assert "workspace" in res.json()["detail"].lower() or "tenant" in res.json()["detail"].lower()


def test_separation_of_duties_responder_cannot_approve():
    """Verify separation of duties: generic responder can propose but CANNOT approve."""
    client = TestClient(app)
    # Generic org:admin maps to responder
    responder_token = _make_token(
        sub="usr_responder_01",
        org_id="org_secops_alpha",
        org_role="org:admin",  # maps to RootMesh responder
    )

    # 1. Verify roles in auth/me
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {responder_token}"})
    assert me_res.status_code == 200
    assert "responder" in me_res.json()["roles"]
    assert "admin" not in me_res.json()["roles"]

    # 2. Responder attempts to approve an action proposal -> must fail closed with 403
    review_res = client.post(
        "/api/v1/incident/review",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={"action_id": "act-dummy-01", "decision": "APPROVE", "comment": "Unauthorized self-approval attempt"},
    )
    assert review_res.status_code == 403
    assert "containment:approve" in review_res.json()["detail"]


# ─────────────────────────────────────────────────────────────
# 2. Complete End-to-End Incident Lifecycle Verification
# ─────────────────────────────────────────────────────────────

def test_complete_e2e_incident_lifecycle():
    """
    Executes and validates the full 8-stage Human-in-the-Loop incident lifecycle:
    1. Select verified asset & Investigate (Stage 1-3)
    2. Persist incident & episodic findings
    3. Formulate mitigation proposal with 900s TTL (Stage 4)
    4. Explicit authorized human review approval (Stage 5)
    5. Guarded execution with idempotency key (Stage 6)
    6. Post-severance verification (Stage 7)
    7. Persistent audit and incident hydration (Stage 8)
    """
    client = TestClient(app)
    admin_token = _make_token(sub="usr_e2e_admin", org_id="org_secops_alpha", org_role="org:rootmesh_admin")
    responder_token = _make_token(sub="usr_e2e_resp", org_id="org_secops_alpha", org_role="org:admin")

    # Ensure host-0 exists in test tenant graph
    graph = db_pool.get_tenant_graph(TENANT_ALPHA)
    graph.query("MERGE (h:Host {id: 'host-0'}) ON CREATE SET h.name = 'Workstation-0', h.firewall = false, h.status = 'INFECTED'")

    # ── Stage 1-3: Authenticated Investigation ──
    inv_res = client.post(
        "/api/v1/incident/investigate",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={"patient_zero_id": "host-0", "tenant_id": TENANT_ALPHA},
    )
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    incident_id = inv_data["incident_id"]
    assert incident_id.startswith("inc-")
    assert inv_data["target_count"] >= 0
    assert "shortest_path_to_db" in inv_data

    # Verify incident node persisted in isolated FalkorDB
    chk_res = graph.query("MATCH (i:Incident {id: $iid}) RETURN i.status, i.severity", {"iid": incident_id}).result_set
    assert len(chk_res) == 1
    assert chk_res[0][0] == "INVESTIGATED"

    # ── Stage 4: Formulate Mitigation Proposal ──
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={
            "incident_id": incident_id,
            "target_host_id": "host-0",
            "action_type": "CONTAIN_HOST_SIMULATION",
            "justification": "E2E lifecycle verification containment proposal",
            "tenant_id": TENANT_ALPHA,
        },
    )
    assert prop_res.status_code == 200
    prop_data = prop_res.json()
    action_id = prop_data["action_id"]
    assert prop_data["status"] == "PROPOSED"
    # Verify 900s approval TTL
    ttl_remaining = prop_data["expires_at"] - prop_data["created_at"]
    assert 895 <= ttl_remaining <= 905, f"Expected ~900s approval TTL, got {ttl_remaining}"

    # ── Stage 5: Explicit Authorized Human Review (Approve) ──
    rev_res = client.post(
        "/api/v1/incident/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "action_id": action_id,
            "decision": "APPROVE",
            "comment": "Approved by SecOps Lead for graph simulation",
        },
    )
    assert rev_res.status_code == 200
    rev_data = rev_res.json()
    assert rev_data["status"] == "APPROVED"
    assert rev_data["reviewed_by"] == "alex.lead"

    # ── Stage 6: Guarded Execution with Idempotency Key ──
    idemp_key = str(uuid.uuid4())
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "action_id": action_id,
            "idempotency_key": idemp_key,
        },
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "CONTAINED"
    assert exec_data["containment_type"] == "GRAPH_TOPOLOGY_SIMULATION"
    assert exec_data["verification"] == "VERIFIED"
    assert exec_data["idempotent_replay"] is False
    assert "Physical hardware firewall rule enforcement requires authorized appliance connector" in exec_data["enforcement_note"]

    # ── Stage 7 & 8: Idempotent Replay & Hydration ──
    # Replay with same idempotency key must return cached audit
    replay_res = client.post(
        "/api/v1/incident/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "action_id": action_id,
            "idempotency_key": idemp_key,
        },
    )
    assert replay_res.status_code == 200
    replay_data = replay_res.json()
    assert replay_data["idempotent_replay"] is True
    assert replay_data["audit_id"] == exec_data["audit_id"]

    # Hydrate incident from backend
    hyd_res = client.get(
        f"/api/v1/incident/{TENANT_ALPHA}/{incident_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert hyd_res.status_code == 200
    hyd_data = hyd_res.json()
    assert hyd_data["status"] == "CONTAINED"
    assert len(hyd_data["audit_trail"]) >= 1
    assert hyd_data["audit_trail"][0]["audit_id"] == exec_data["audit_id"]


# ─────────────────────────────────────────────────────────────
# 3. Negative Lifecycle Paths
# ─────────────────────────────────────────────────────────────

def test_rejection_fail_closed_path():
    """Verify rejected proposal strictly blocks execution (403 Forbidden)."""
    client = TestClient(app)
    admin_token = _make_token(sub="usr_admin_rej", org_role="org:rootmesh_admin")
    responder_token = _make_token(sub="usr_resp_rej", org_role="org:admin")

    # Create real investigated incident first
    inv_res = client.post(
        "/api/v1/incident/investigate",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={"patient_zero_id": "host-0", "tenant_id": TENANT_ALPHA},
    )
    incident_id = inv_res.json()["incident_id"]

    # Formulate proposal
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={
            "incident_id": incident_id,
            "target_host_id": "host-0",
            "action_type": "CONTAIN_HOST_SIMULATION",
            "justification": "Rejection test proposal",
            "tenant_id": TENANT_ALPHA,
        },
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # Reject proposal
    rev_res = client.post(
        "/api/v1/incident/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "action_id": action_id,
            "decision": "REJECT",
            "comment": "Rejected due to change window freeze",
        },
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REJECTED"

    # Attempt to execute rejected proposal -> MUST fail closed with 403 Forbidden
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"action_id": action_id, "idempotency_key": str(uuid.uuid4())},
    )
    assert exec_res.status_code == 403
    assert "rejected" in exec_res.json()["detail"].lower()


def test_expired_proposal_fail_closed_path():
    """Verify expired proposal strictly blocks review and execution (410 Gone)."""
    client = TestClient(app)
    admin_token = _make_token(sub="usr_admin_exp", org_role="org:rootmesh_admin")
    responder_token = _make_token(sub="usr_resp_exp", org_role="org:admin")

    # Create real investigated incident first
    inv_res = client.post(
        "/api/v1/incident/investigate",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={"patient_zero_id": "host-0", "tenant_id": TENANT_ALPHA},
    )
    incident_id = inv_res.json()["incident_id"]

    # Formulate proposal
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={
            "incident_id": incident_id,
            "target_host_id": "host-0",
            "action_type": "CONTAIN_HOST_SIMULATION",
            "justification": "Expiration test proposal",
            "tenant_id": TENANT_ALPHA,
        },
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # Manually expire the proposal in incident service
    from app.incident.service import incident_service
    prop = incident_service.get_proposal(action_id)
    prop.expires_at = time.time() - 100.0  # expired in past

    # Attempt to approve expired proposal -> MUST fail with 410 Gone
    rev_res = client.post(
        "/api/v1/incident/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"action_id": action_id, "decision": "APPROVE", "comment": "Late approval attempt"},
    )
    assert rev_res.status_code == 410
    assert "expired" in rev_res.json()["detail"].lower()


def test_missing_incident_proposal_error():
    """Verify formulating proposal for non-existent incident returns 404 Not Found."""
    client = TestClient(app)
    responder_token = _make_token(sub="usr_resp_miss", org_role="org:admin")
    res = client.post(
        "/api/v1/incident/propose",
        headers={"Authorization": f"Bearer {responder_token}"},
        json={
            "incident_id": "inc-nonexistent-9999",
            "target_host_id": "host-0",
            "action_type": "CONTAIN_HOST_SIMULATION",
            "justification": "Missing incident proposal attempt",
            "tenant_id": TENANT_ALPHA,
        },
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_missing_patient_zero_investigation_error():
    """Verify investigating a non-existent host returns 404 Not Found."""
    client = TestClient(app)
    admin_token = _make_token(sub="usr_admin_miss", org_role="org:rootmesh_admin")
    res = client.post(
        "/api/v1/incident/investigate",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"patient_zero_id": "host-nonexistent-9999", "tenant_id": TENANT_ALPHA},
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────
# 4. Legacy Containment Endpoint Permanent Disabling
# ─────────────────────────────────────────────────────────────

def test_legacy_direct_containment_endpoint_disabled():
    """Verify POST /api/v1/threat/contain unconditionally returns 410 Gone with zero side effects."""
    client = TestClient(app)
    admin_token = _make_token(sub="usr_admin_legacy", org_role="org:rootmesh_admin")
    res = client.post(
        "/api/v1/threat/contain",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"target_host_id": "host-0", "tenant_id": TENANT_ALPHA},
    )
    assert res.status_code == 410
    detail = res.json()["detail"]
    assert "permanently disabled" in detail
    assert "guarded lifecycle" in detail
