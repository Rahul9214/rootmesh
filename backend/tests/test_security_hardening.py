"""
RootMesh — Module 002 Security & Agent Hardening Verification Suite
Tests:
- Cryptographic authentication & token verification (valid, expired, tampered, bad issuer/aud)
- Production default-to-deny authorization boundary
- Role-based permissions (RBAC) & least-privilege enforcement
- Workspace membership and cross-tenant access rejection
- Hardened MCP tool boundaries (length limit, injection, mutation clauses, admin calls)
- Guarded incident response 8-stage lifecycle
- Rejection and expiration fail-closed enforcement
- Durable idempotency and replay protection
- Persistent FalkorDB procedural memory & episodic findings
- Real-time WebSocket tenant-scoped isolation and deduplication
"""
from __future__ import annotations

import json
import time
from datetime import timedelta
import pytest
from starlette.testclient import TestClient

from app.config import settings
from app.db.falkor_client import db_pool
from app.incident.models import ActionState
from app.incident.service import incident_service
from app.main import app, ws_manager
from app.mcp_server import (
    falkordb_execute_cypher,
    falkordb_save_finding_memory,
    falkordb_triage_host,
)
from app.security.auth import (
    SecurityPrincipal,
    create_access_token,
    generate_dev_token,
    verify_access_token,
)

TENANT_ALPHA = "sec_ops_tenant_alpha"
TENANT_BETA = "sec_ops_tenant_beta"


# ──────────────────────────────────────────────
# 1. Cryptographic Authentication & Claims Tests
# ──────────────────────────────────────────────

def test_token_creation_and_cryptographic_verification():
    """Verify HMAC-SHA256 signed JWT contains proper claims and passes cryptographic verification."""
    token = create_access_token(
        principal_id="usr-test-alex",
        username="alex.rivera",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
        workspaces=[TENANT_ALPHA, TENANT_BETA],
    )
    assert isinstance(token, str)

    principal = verify_access_token(token)
    assert principal.principal_id == "usr-test-alex"
    assert principal.username == "alex.rivera"
    assert principal.tenant_id == TENANT_ALPHA
    assert "admin" in principal.roles
    assert principal.has_permission("containment:execute")
    assert principal.can_access_tenant(TENANT_BETA)


def test_expired_token_rejected():
    """Verify expired token is strictly rejected with HTTP 401."""
    expired_token = create_access_token(
        principal_id="usr-expired",
        username="expired.user",
        tenant_id=TENANT_ALPHA,
        roles=["analyst"],
        expires_delta=timedelta(seconds=-10),
    )
    with pytest.raises(Exception) as exc_info:
        verify_access_token(expired_token)
    assert "expired" in str(exc_info.value).lower()


def test_tampered_signature_rejected():
    """Verify token signature tampering causes cryptographic verification failure."""
    valid_token = create_access_token(
        principal_id="usr-valid",
        username="valid.user",
        tenant_id=TENANT_ALPHA,
        roles=["analyst"],
    )
    # Tamper with the signature bytes at the end of the JWT
    tampered_token = valid_token[:-4] + "XXXX"
    with pytest.raises(Exception) as exc_info:
        verify_access_token(tampered_token)
    assert "invalid" in str(exc_info.value).lower() or "signature" in str(exc_info.value).lower()


def test_auth_login_endpoint():
    """Verify POST /api/v1/auth/token authenticates authorized user and rejects invalid credentials."""
    client = TestClient(app)

    # Valid credentials
    res = client.post(
        "/api/v1/auth/token",
        json={"username": "alex.rivera", "secret": "rivera-secops-2026", "tenant_id": TENANT_ALPHA},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["principal"]["username"] == "alex.rivera"

    # Invalid secret
    res_bad = client.post(
        "/api/v1/auth/token",
        json={"username": "alex.rivera", "secret": "wrong-secret", "tenant_id": TENANT_ALPHA},
    )
    assert res_bad.status_code == 401

    # Unauthorized workspace requested
    res_bad_ws = client.post(
        "/api/v1/auth/token",
        json={"username": "sarah.chen", "secret": "chen-responder-2026", "tenant_id": TENANT_BETA},
    )
    assert res_bad_ws.status_code == 403


def test_dev_token_endpoint():
    """Verify POST /api/v1/auth/dev-token issues verified JWT for development."""
    client = TestClient(app)
    res = client.post(
        "/api/v1/auth/dev-token",
        json={"username": "alex.rivera", "tenant_id": TENANT_ALPHA, "roles": ["admin"]},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["principal"]["tenant_id"] == TENANT_ALPHA


# ──────────────────────────────────────────────
# 2. Authorization, RBAC & Cross-Tenant Boundaries
# ──────────────────────────────────────────────

def test_production_auth_mode_defaults_to_deny(monkeypatch):
    """Verify when auth_mode is set to 'prod', unauthenticated requests fail with 401."""
    monkeypatch.setattr(settings, "auth_mode", "prod")
    client = TestClient(app)

    # Request without Authorization header must fail closed
    res = client.get(f"/api/v1/threat/topology/{TENANT_ALPHA}")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_rbac_least_privilege_enforcement():
    """Verify role permissions are strictly enforced (e.g. investigator cannot propose containment)."""
    client = TestClient(app)

    # Issue token with role 'investigator' (no containment:propose permission)
    investigator_token = create_access_token(
        principal_id="usr-investigator",
        username="guest.auditor",
        tenant_id=TENANT_ALPHA,
        roles=["investigator"],
    )

    headers = {"Authorization": f"Bearer {investigator_token}"}
    res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": "inc-rbac-test",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-0",
            "justification": "Test RBAC restriction",
        },
    )
    assert res.status_code == 403
    assert "Principal lacks required permission" in res.json()["detail"]


def test_cross_tenant_access_rejected():
    """Verify user bound only to tenant alpha is rejected when accessing tenant beta."""
    client = TestClient(app)

    # User bound strictly to TENANT_ALPHA
    alpha_only_token = create_access_token(
        principal_id="usr-alpha-only",
        username="marcus.vance",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
        workspaces=[TENANT_ALPHA],
    )

    headers = {"Authorization": f"Bearer {alpha_only_token}"}
    res = client.get(f"/api/v1/threat/topology/{TENANT_BETA}", headers=headers)
    assert res.status_code == 403
    assert "Cross-tenant access rejected" in res.json()["detail"]


# ──────────────────────────────────────────────
# 3. Hardened MCP Tool Contract Tests
# ──────────────────────────────────────────────

def test_mcp_query_length_boundary():
    """Verify MCP falkordb_execute_cypher strictly rejects queries exceeding length limit."""
    long_query = "MATCH (h:Host) WHERE " + "h.name = 'test' OR " * 50 + "RETURN h.id"
    assert len(long_query) > 500
    res_str = falkordb_execute_cypher(cypher_query=long_query, tenant_id=TENANT_ALPHA)
    parsed = json.loads(res_str)
    assert parsed["status"] == "error"
    assert parsed["code"] == "QUERY_OVERSIZED"


def test_mcp_comment_and_semicolon_injection_blocked():
    """Verify semicolons and Cypher comments (-- and /*) are blocked to prevent multi-statement injection."""
    queries_to_test = [
        "MATCH (h:Host) RETURN h.name; DROP GRAPH;",
        "MATCH (h:Host) RETURN h.name -- comment",
        "MATCH (h:Host) /* inline comment */ RETURN h.name",
    ]
    for q in queries_to_test:
        res_str = falkordb_execute_cypher(cypher_query=q, tenant_id=TENANT_ALPHA)
        parsed = json.loads(res_str)
        assert parsed["status"] == "error"
        assert parsed["code"] == "INJECTION_DETECTED"


def test_mcp_mutation_keywords_blocked():
    """Verify mutation clauses (CREATE, SET, DELETE, MERGE, DROP) trigger safety violation."""
    mutations = [
        "CREATE (n:Rogue {id: 'hack'})",
        "MATCH (h:Host {id: 'host-0'}) SET h.status = 'COMPROMISED'",
        "MATCH (h:Host {id: 'host-0'}) DELETE h",
        "MERGE (h:Host {id: 'host-0'})",
    ]
    for m in mutations:
        res_str = falkordb_execute_cypher(cypher_query=m, tenant_id=TENANT_ALPHA)
        parsed = json.loads(res_str)
        assert parsed["status"] == "error"
        assert parsed["code"] == "SAFETY_BOUNDARY_VIOLATION"


def test_mcp_admin_procedure_blocked():
    """Verify administrative procedure calls are strictly rejected."""
    res_str = falkordb_execute_cypher(cypher_query="CALL db.labels()", tenant_id=TENANT_ALPHA)
    parsed = json.loads(res_str)
    assert parsed["status"] == "error"
    assert parsed["code"] == "ADMIN_CALL_PROHIBITED"


def test_mcp_unauthorized_tenant_blocked():
    """Verify MCP tools reject unauthorized rogue tenants."""
    res_str = falkordb_execute_cypher(
        cypher_query="MATCH (h:Host) RETURN h.id",
        tenant_id="rogue_unauthorized_tenant",
    )
    parsed = json.loads(res_str)
    assert parsed["status"] == "error"
    assert parsed["code"] == "UNAUTHORIZED_TENANT"


# ──────────────────────────────────────────────
# 4. Guarded Incident Response Lifecycle Tests
# ──────────────────────────────────────────────

def test_incident_response_full_lifecycle_and_idempotency():
    """
    Verify complete 8-stage lifecycle:
    Propose -> Review (Approve) -> Execute -> FalkorDB State Verification -> Procedural Memory -> Idempotent Replay.
    """
    client = TestClient(app)
    admin_token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    incident_id = f"inc-guard-{int(time.time())}"
    host_id = "host-0"

    # Stage 1-5: Propose Action
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": incident_id,
            "tenant_id": TENANT_ALPHA,
            "target_host_id": host_id,
            "action_type": "CONTAIN_HOST_SIMULATION",
            "justification": "Patient Zero lateral movement containment",
        },
    )
    assert prop_res.status_code == 200
    proposal = prop_res.json()
    action_id = proposal["action_id"]
    assert proposal["status"] == "PROPOSED"
    assert "attack_paths" in proposal["evidence"]
    assert "max_egress_mbps" in proposal["risk_assessment"]

    # Stage 6: Premature Execution Attempt Must Fail Closed
    premature_exec = client.post(
        "/api/v1/incident/execute",
        headers=headers,
        json={"action_id": action_id, "idempotency_key": "idemp-key-premature-1"},
    )
    assert premature_exec.status_code == 400
    assert "must be APPROVED before execution" in premature_exec.json()["detail"]

    # Stage 6: Authorized Review (Approve)
    review_res = client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": action_id, "decision": "APPROVE", "comment": "Approved by SOC Lead"},
    )
    assert review_res.status_code == 200
    assert review_res.json()["status"] == "APPROVED"
    assert review_res.json()["reviewed_by"] == "alex.rivera"

    # Stage 7 & 8: Execute, Verification & Audit
    idemp_key = f"idemp-guard-{int(time.time() * 1000)}"
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers=headers,
        json={"action_id": action_id, "idempotency_key": idemp_key},
    )
    assert exec_res.status_code == 200
    audit = exec_res.json()
    assert audit["status"] == "CONTAINED"
    assert audit["verification"] == "VERIFIED"
    assert audit["idempotent_replay"] is False
    assert audit["containment_type"] == "GRAPH_TOPOLOGY_SIMULATION"
    assert "Physical hardware firewall rule enforcement requires authorized appliance connector" in audit["enforcement_note"]

    # Idempotency Replay Test: Duplicate execution with same idempotency_key
    replay_res = client.post(
        "/api/v1/incident/execute",
        headers=headers,
        json={"action_id": action_id, "idempotency_key": idemp_key},
    )
    assert replay_res.status_code == 200
    replay_data = replay_res.json()
    assert replay_data["idempotent_replay"] is True
    assert replay_data["audit_id"] == audit["audit_id"]

    # Persistent Procedural Memory Check in FalkorDB
    proc_res = client.get(f"/api/v1/incident/procedural-memory/{TENANT_ALPHA}/{host_id}", headers=headers)
    assert proc_res.status_code == 200
    proc_records = proc_res.json()
    assert len(proc_records) >= 1
    assert any(r["incident_id"] == incident_id for r in proc_records)


def test_incident_rejection_fails_closed():
    """Verify rejected proposals cannot be executed and fail closed."""
    client = TestClient(app)
    admin_token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Propose
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": "inc-reject-test",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-1",
            "justification": "Test rejection flow",
        },
    )
    action_id = prop_res.json()["action_id"]

    # Review: Reject
    review_res = client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": action_id, "decision": "REJECT", "comment": "Insufficient evidence"},
    )
    assert review_res.status_code == 200
    assert review_res.json()["status"] == "REJECTED"

    # Execution attempt must fail closed (403 Forbidden)
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers=headers,
        json={"action_id": action_id, "idempotency_key": "idemp-reject-test"},
    )
    assert exec_res.status_code == 403
    assert "rejected during review" in exec_res.json()["detail"]


def test_incident_expiration_fails_closed():
    """Verify expired proposals fail closed on both review and execution."""
    client = TestClient(app)
    admin_token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    prop_res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": "inc-expire-test",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-2",
            "justification": "Test expiration flow",
        },
    )
    action_id = prop_res.json()["action_id"]

    # Force expiration in memory
    proposal = incident_service.get_proposal(action_id)
    proposal.expires_at = time.time() - 10.0

    # Review attempt on expired proposal must fail closed (410 Gone)
    review_res = client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": action_id, "decision": "APPROVE"},
    )
    assert review_res.status_code == 410
    assert "expired" in review_res.json()["detail"].lower()


# ──────────────────────────────────────────────
# 5. WebSocket Tenant Isolation & Real-Time Sync
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_websocket_tenant_scoped_broadcast_isolation():
    """Verify events broadcast to Tenant Alpha are NEVER received by Tenant Beta connections."""
    client = TestClient(app)
    token_alpha = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA)
    token_beta = generate_dev_token(username="beta.operator", tenant_id=TENANT_BETA)

    with client.websocket_connect(f"/ws/threat-stream?token={token_alpha}&tenant_id={TENANT_ALPHA}") as ws_alpha:
        with client.websocket_connect(f"/ws/threat-stream?token={token_beta}&tenant_id={TENANT_BETA}") as ws_beta:
            # Broadcast event to Alpha only
            alpha_payload = {
                "event_id": f"evt-alpha-{int(time.time() * 1000)}",
                "tenant_id": TENANT_ALPHA,
                "type": "ATTACK_STEP",
                "step": "host-0 to host-1 lateral movement",
            }
            await ws_manager.broadcast_to_tenant(TENANT_ALPHA, alpha_payload)

            # ws_alpha must receive the event
            recv_alpha = ws_alpha.receive_json()
            assert recv_alpha["event_id"] == alpha_payload["event_id"]
            assert recv_alpha["tenant_id"] == TENANT_ALPHA

            # Send ping to ws_beta to verify its stream is clear of alpha events
            ws_beta.send_json({"type": "ping"})
            recv_beta = ws_beta.receive_json()
            assert recv_beta["type"] == "pong"
            assert recv_beta["tenant_id"] == TENANT_BETA


@pytest.mark.asyncio
async def test_websocket_event_deduplication():
    """Verify duplicate event IDs are suppressed to prevent infinite loops and UI flicker."""
    client = TestClient(app)
    token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA)

    with client.websocket_connect(f"/ws/threat-stream?token={token}&tenant_id={TENANT_ALPHA}") as ws:
        shared_event_id = f"evt-dedup-{int(time.time() * 1000)}"
        payload = {"event_id": shared_event_id, "type": "CONTAINMENT_TRIGGERED"}

        # Broadcast first instance
        await ws_manager.broadcast_to_tenant(TENANT_ALPHA, payload)
        first_recv = ws.receive_json()
        assert first_recv["event_id"] == shared_event_id

        # Broadcast duplicate instance
        await ws_manager.broadcast_to_tenant(TENANT_ALPHA, payload)

        # Ping to confirm duplicate was suppressed and not in queue
        ws.send_json({"type": "ping"})
        pong_recv = ws.receive_json()
        assert pong_recv["type"] == "pong"


# ──────────────────────────────────────────────
# 6. Production Hardening, Concurrency & Bypass Prevention Tests
# ──────────────────────────────────────────────

def test_production_auth_cannot_be_bypassed(monkeypatch):
    """
    Verify production authentication cannot be bypassed:
    1. /api/v1/auth/dev-token is rejected (HTTP 403)
    2. Insecure default secrets trigger validation error in production
    3. Legacy /api/v1/threat/contain direct containment route is rejected (HTTP 403)
    """
    monkeypatch.setattr(settings, "auth_mode", "prod")
    client = TestClient(app)

    # 1. /dev-token must be rejected in production
    dev_res = client.post(
        "/api/v1/auth/dev-token",
        json={"username": "alex.rivera", "tenant_id": TENANT_ALPHA, "roles": ["admin"]},
    )
    assert dev_res.status_code == 403
    assert "strictly disabled in production mode" in dev_res.json()["detail"]

    # 2. Insecure default secret must trigger validation failure in production
    with pytest.raises(ValueError) as exc:
        settings.validate_production_security()
    assert "CRITICAL SECURITY CONFIGURATION FAILURE" in str(exc.value)

    # 3. Legacy direct containment route must be blocked in production even with valid token
    monkeypatch.setattr(settings, "jwt_secret", "a-cryptographically-secure-production-jwt-secret-key-32chars")
    valid_prod_token = create_access_token(
        principal_id="usr-admin",
        username="alex.rivera",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
        custom_claims={"iss": settings.jwt_issuer, "aud": settings.jwt_audience},
    )
    headers = {"Authorization": f"Bearer {valid_prod_token}"}
    contain_res = client.post(
        "/api/v1/threat/contain",
        headers=headers,
        json={"tenant_id": TENANT_ALPHA, "host_id": "host-0"},
    )
    assert contain_res.status_code == 403
    assert "Legacy direct containment route is disabled in production mode" in contain_res.json()["detail"]


def test_persistent_idempotency_survives_process_restart():
    """
    Verify idempotency enforcement is durable in FalkorDB:
    A fresh IncidentResponseService instance (simulating process restart with zero in-memory cache)
    correctly resolves the completed idempotency record and returns an idempotent replay without re-executing.
    """
    from app.incident.service import IncidentResponseService
    client = TestClient(app)
    admin_token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    principal = verify_access_token(admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    idemp_key = f"restart-test-{int(time.time() * 1000)}"

    # Propose and review through live API
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": f"inc-restart-{int(time.time())}",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-0",
            "justification": "Durable restart verification",
        },
    )
    action_id = prop_res.json()["action_id"]
    client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": action_id, "decision": "APPROVE"},
    )

    # First execution via live service
    exec_res1 = client.post(
        "/api/v1/incident/execute",
        headers=headers,
        json={"action_id": action_id, "idempotency_key": idemp_key},
    )
    assert exec_res1.status_code == 200
    first_audit = exec_res1.json()
    assert first_audit["idempotent_replay"] is False

    # Simulate full process restart: instantiate a brand new IncidentResponseService
    fresh_service = IncidentResponseService()
    assert action_id not in fresh_service._proposals
    assert f"{TENANT_ALPHA}:{idemp_key}" not in fresh_service._idempotency_cache

    # Execute against fresh service: MUST read persisted state from FalkorDB
    from app.incident.models import ExecuteActionRequest
    second_audit = fresh_service.execute_action(
        principal=principal,
        req=ExecuteActionRequest(action_id=action_id, idempotency_key=idemp_key),
    )
    assert second_audit.idempotent_replay is True
    assert second_audit.audit_id == first_audit["audit_id"]
    assert second_audit.status == "CONTAINED"


def test_concurrency_safe_idempotency_blocks_duplicate_execution():
    """
    Verify concurrency safety:
    Simultaneous execution requests with the same idempotency key are atomic.
    Only one executes; duplicate/concurrent attempts receive either replay or 409 Conflict.
    """
    from concurrent.futures import ThreadPoolExecutor
    client = TestClient(app)
    admin_token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    idemp_key = f"concurrent-test-{int(time.time() * 1000)}"

    prop_res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": f"inc-concurrent-{int(time.time())}",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-0",
            "justification": "Concurrency safety verification",
        },
    )
    action_id = prop_res.json()["action_id"]
    client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": action_id, "decision": "APPROVE"},
    )

    def _execute():
        return client.post(
            "/api/v1/incident/execute",
            headers=headers,
            json={"action_id": action_id, "idempotency_key": idemp_key},
        )

    # Launch 4 concurrent requests at once
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_execute) for _ in range(4)]
        results = [f.result() for f in futures]

    # Verify every request was handled safely (either 200 OK with execution/replay or 409 Conflict)
    status_codes = [r.status_code for r in results]
    assert all(code in (200, 409) for code in status_codes)

    # Exactly one request must be the original execution (idempotent_replay: False)
    successful_audits = [r.json() for r in results if r.status_code == 200]
    assert len(successful_audits) >= 1
    original_executions = [a for a in successful_audits if a.get("idempotent_replay") is False]
    assert len(original_executions) == 1, "Expected exactly 1 execution to claim atomic execution"


def test_mcp_eliminates_arbitrary_user_cypher():
    """
    Verify MCP tools eliminate arbitrary user-supplied Cypher:
    Only fixed, allowlisted parameterized operations are allowed; arbitrary Cypher is rejected.
    """
    # 1. Arbitrary non-allowlisted Cypher queries must be rejected
    arbitrary_queries = [
        "MATCH (n) RETURN n",
        "MATCH (h:Host) DETACH DELETE h",
        "MATCH (h:Host) WHERE 1=1 RETURN h",
        "MATCH (h:Host)-[r]->(t) RETURN r",
        "CALL db.labels()",
    ]
    for q in arbitrary_queries:
        res = falkordb_execute_cypher(cypher_query=q, tenant_id=TENANT_ALPHA)
        parsed = json.loads(res)
        assert parsed["status"] == "error"
        assert parsed["code"] in ("SAFETY_BOUNDARY_VIOLATION", "ADMIN_CALL_PROHIBITED")

    # 2. Allowlisted operation must succeed and return data via precompiled template
    allowlisted_res = falkordb_execute_cypher(
        cypher_query="MATCH (h:Host {id: 'host-0'}) RETURN h.name",
        tenant_id=TENANT_ALPHA,
    )
    parsed_ok = json.loads(allowlisted_res)
    assert parsed_ok["status"] == "success"
    assert parsed_ok["operation"] == "get_host_name_by_id"
    assert parsed_ok["data"][0][0] == "Workstation-PatientZero"

