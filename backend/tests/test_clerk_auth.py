"""
RootMesh — Clerk B2B Authentication & Authorization Verification Suite
Tests official RS256 Clerk session verification, issuer/audience/expiry/nbf checks,
organization mapping, tenant context isolation, RBAC role enforcement,
separation of duties (containment proposal vs approval/execution),
legacy authentication rejection, and authenticated WebSockets.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.security.auth import (
    ROLE_PERMISSIONS,
    create_test_clerk_token,
    verify_access_token,
    verify_clerk_token,
)

# ──────────────────────────────────────────────
# Cryptographic Test Fixtures
# ──────────────────────────────────────────────

# Legitimate Clerk test key pair
_valid_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_valid_public_pem = _valid_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

# Adversarial key pair for tampered / mismatched signature tests
_attacker_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

from app.db.test_guard import TEST_TENANT_ALPHA, TEST_TENANT_BETA

TENANT_ALPHA = TEST_TENANT_ALPHA
TENANT_BETA = TEST_TENANT_BETA
CLERK_ISSUER = "https://clerk.rootmesh.security"



@pytest.fixture(autouse=True)
def setup_clerk_test_env(monkeypatch):
    """Configures backend settings to use test Clerk public key and trusted org map."""
    monkeypatch.setattr(settings, "clerk_pem_public_key", _valid_public_pem)
    monkeypatch.setattr(settings, "clerk_issuer", CLERK_ISSUER)
    monkeypatch.setattr(settings, "clerk_authorized_parties", "http://localhost:3000,http://127.0.0.1:3000")
    monkeypatch.setattr(
        settings,
        "clerk_org_to_tenant_map",
        json.dumps({
            "org_2secops_alpha": TENANT_ALPHA,
            "org_2secops_beta": TENANT_BETA,
        }),
    )


# ──────────────────────────────────────────────
# 1. Clerk RS256 Verification & Validation Tests
# ──────────────────────────────────────────────

def test_valid_clerk_session_token_verification():
    """Verify legitimate RS256 Clerk session token is verified with accurate claims and mapped tenant."""
    token = create_test_clerk_token(
        sub="user_2clerk_sarah",
        username="sarah.chen",
        email="sarah.chen@company.com",
        org_id="org_2secops_alpha",
        org_role="org:admin",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    principal = verify_access_token(token)
    assert principal.principal_id == "user_2clerk_sarah"
    assert principal.username == "sarah.chen"
    assert principal.email == "sarah.chen@company.com"
    assert principal.tenant_id == TENANT_ALPHA
    # Clerk org:admin maps to RootMesh responder (enforces separation of duties)
    assert principal.roles == ["responder"]
    assert "incident:investigate" in principal.permissions
    assert "containment:propose" in principal.permissions
    # Cannot approve or execute containment
    assert "containment:approve" not in principal.permissions
    assert "containment:execute" not in principal.permissions


def test_invalid_signature_rejected():
    """Verify Clerk session token signed with untrusted private key is rejected with 401."""
    tampered_token = create_test_clerk_token(
        sub="user_2attacker",
        username="attacker",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_attacker_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(tampered_token)

    assert exc_info.value.status_code == 401
    assert "invalid cryptographic signature" in exc_info.value.detail.lower()


def test_expired_clerk_session_rejected():
    """Verify expired Clerk session token is rejected with 401."""
    expired_token = create_test_clerk_token(
        sub="user_2expired",
        username="expired.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        expires_in_seconds=-60,  # Expired 1 minute ago
        private_key=_valid_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(expired_token)

    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_future_not_before_rejected():
    """Verify Clerk session token with nbf in the future is rejected with 401."""
    future_token = create_test_clerk_token(
        sub="user_2future",
        username="future.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        nbf_offset_seconds=300,  # Valid 5 minutes in the future
        private_key=_valid_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(future_token)

    assert exc_info.value.status_code == 401
    assert "not yet valid" in exc_info.value.detail.lower()


def test_mismatched_issuer_rejected():
    """Verify Clerk session token with wrong issuer is rejected with 401."""
    wrong_issuer_token = create_test_clerk_token(
        sub="user_2imposter",
        username="imposter",
        org_id="org_2secops_alpha",
        issuer="https://evil-clerk-instance.com",
        private_key=_valid_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(wrong_issuer_token)

    assert exc_info.value.status_code == 401
    assert "invalid token issuer" in exc_info.value.detail.lower()


def test_unauthorized_party_azp_rejected():
    """Verify Clerk session token from unauthorized frontend origin is rejected with 401."""
    unauthorized_azp_token = create_test_clerk_token(
        sub="user_2phisher",
        username="phisher",
        org_id="org_2secops_alpha",
        azp="https://unauthorized-phishing-domain.com",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(unauthorized_azp_token)

    assert exc_info.value.status_code == 401
    assert "authorized party" in exc_info.value.detail.lower()


# ──────────────────────────────────────────────
# 2. Organization Context & Cross-Tenant Access
# ──────────────────────────────────────────────

def test_missing_organization_membership_rejected():
    """Verify Clerk session token without org_id is rejected with 403 Forbidden."""
    personal_token = create_test_clerk_token(
        sub="user_2personal",
        username="personal.user",
        org_id="",  # No org selected
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(personal_token)

    assert exc_info.value.status_code == 403
    assert "organization context" in exc_info.value.detail.lower()


def test_unmapped_organization_rejected():
    """Verify Clerk organization ID not mapped in server-side configuration is rejected with 403."""
    unmapped_token = create_test_clerk_token(
        sub="user_2foreign",
        username="foreign.user",
        org_id="org_foreign_unregistered_999",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(unmapped_token)

    assert exc_info.value.status_code == 403
    assert "not mapped to an authorized rootmesh tenant" in exc_info.value.detail.lower()


def test_cross_tenant_access_rejected_with_clerk_token():
    """Verify user in Org Alpha cannot access resources in Tenant Beta."""
    client = TestClient(app)
    alpha_token = create_test_clerk_token(
        sub="user_2alpha",
        username="alpha.analyst",
        org_id="org_2secops_alpha",
        org_role="org:member",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )
    headers = {"Authorization": f"Bearer {alpha_token}"}

    # Attempt accessing Tenant Beta resources
    res = client.get(f"/api/v1/threat/topology/{TENANT_BETA}", headers=headers)
    assert res.status_code == 403
    assert "Cross-tenant access rejected" in res.json()["detail"]


# ──────────────────────────────────────────────
# 3. RBAC Least Privilege & Separation of Duties
# ──────────────────────────────────────────────

def test_clerk_org_admin_cannot_approve_containment():
    """
    SEPARATION OF DUTIES ENFORCEMENT:
    A Clerk organization administrator does NOT automatically receive RootMesh admin powers.
    Clerk org:admin maps to 'responder', allowing investigation & proposal,
    but strictly rejecting containment approval (403 Forbidden).
    """
    client = TestClient(app)
    responder_token = create_test_clerk_token(
        sub="user_2sarah",
        username="sarah.chen",
        org_id="org_2secops_alpha",
        org_role="org:admin",  # Standard Clerk Org Admin -> RootMesh responder
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )
    headers = {"Authorization": f"Bearer {responder_token}"}

    # 1. Propose containment: responder CAN propose
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers=headers,
        json={
            "incident_id": "inc-18c2b368",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-0",
            "justification": "Automated triage lateral traversal severed",
        },
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # 2. Attempt containment approval: responder CANNOT approve
    review_res = client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": action_id, "decision": "APPROVE", "comment": "Unauthorized self-approval attempt"},
    )
    assert review_res.status_code == 403
    assert "Principal lacks required permission 'containment:approve'" in review_res.json()["detail"]

    # 3. Attempt containment execution: responder CANNOT execute
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers=headers,
        json={"action_id": action_id, "idempotency_key": "idemp-unauth-1"},
    )
    assert exec_res.status_code == 403
    assert "Principal lacks required permission 'containment:execute'" in exec_res.json()["detail"]


def test_explicit_rootmesh_admin_can_approve_containment():
    """Verify an explicit RootMesh admin (rootmesh_role='admin') can approve and execute containment."""
    client = TestClient(app)

    # Proposer: responder (Sarah Chen)
    proposer_token = create_test_clerk_token(
        sub="user_2sarah",
        username="sarah.chen",
        org_id="org_2secops_alpha",
        org_role="org:admin",  # Maps to responder
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    # Approver: explicit RootMesh admin (Alex Rivera)
    admin_token = create_test_clerk_token(
        sub="user_2alex",
        username="alex.rivera",
        org_id="org_2secops_alpha",
        org_role="org:rootmesh_admin",
        rootmesh_role="admin",  # Explicit RootMesh admin claim
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    # Propose by Sarah
    prop_res = client.post(
        "/api/v1/incident/propose",
        headers={"Authorization": f"Bearer {proposer_token}"},
        json={
            "incident_id": "inc-18c2b368",
            "tenant_id": TENANT_ALPHA,
            "target_host_id": "host-0",
            "justification": "Lateral spread mitigation proposed",
        },
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # Review by Alex Rivera (Admin)
    review_res = client.post(
        "/api/v1/incident/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"action_id": action_id, "decision": "APPROVE", "comment": "Independent review approved by Lead"},
    )
    assert review_res.status_code == 200
    assert review_res.json()["status"] == "APPROVED"
    assert review_res.json()["reviewed_by"] == "alex.rivera"

    # Execute by Alex Rivera (Admin)
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"action_id": action_id, "idempotency_key": f"idemp-clerk-{int(time.time() * 1000)}"},
    )
    assert exec_res.status_code == 200
    assert exec_res.json()["status"] == "CONTAINED"
    assert exec_res.json()["verification"] == "VERIFIED"


# ──────────────────────────────────────────────
# 4. Legacy Authentication Disabled in Production
# ──────────────────────────────────────────────

def test_legacy_password_login_disabled_in_production(monkeypatch):
    """Verify legacy password login route /api/v1/auth/token is rejected in production (403 Forbidden)."""
    monkeypatch.setattr(settings, "auth_mode", "prod")
    client = TestClient(app)

    res = client.post(
        "/api/v1/auth/token",
        json={"username": "alex.rivera", "secret": "test-dev-credential", "tenant_id": TENANT_ALPHA},
    )
    assert res.status_code == 403
    assert "Legacy password token issuance is disabled in production" in res.json()["detail"]


def test_legacy_hs256_token_rejected_when_clerk_configured():
    """Verify legacy HS256 tokens are rejected with 401 when Clerk authentication is active."""
    from app.security.auth import create_access_token
    legacy_token = create_access_token(
        principal_id="usr-legacy",
        username="legacy.user",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(legacy_token)

    assert exc_info.value.status_code == 401
    assert "legacy tokens are disabled" in exc_info.value.detail.lower()


# ──────────────────────────────────────────────
# 5. Authenticated WebSocket Connections
# ──────────────────────────────────────────────

def test_websocket_connects_with_valid_clerk_token():
    """Verify WebSocket connection succeeds with valid Clerk RS256 token and joins authorized tenant."""
    client = TestClient(app)
    clerk_token = create_test_clerk_token(
        sub="user_2ws_client",
        username="ws.analyst",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    with client.websocket_connect("/ws/threat-stream") as ws:
        ws.send_json({"type": "auth", "token": clerk_token, "tenant_id": TENANT_ALPHA})
        auth_ack = ws.receive_json()
        assert auth_ack["type"] == "auth_ok"
        assert auth_ack["tenant_id"] == TENANT_ALPHA

        ws.send_text(json.dumps({"type": "ping"}))
        resp = ws.receive_json()
        assert resp["type"] == "pong"
        assert resp["tenant_id"] == TENANT_ALPHA


def test_websocket_rejects_cross_tenant_clerk_token():
    """Verify WebSocket connection fails when Clerk token's organization does not match requested tenant."""
    client = TestClient(app)
    # Token for Org Alpha
    clerk_token = create_test_clerk_token(
        sub="user_2ws_cross",
        username="ws.cross",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )

    # Attempting to subscribe to Tenant Beta
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({"type": "auth", "token": clerk_token, "tenant_id": TENANT_BETA})
            ws.receive_json()


def test_websocket_rejects_invalid_signature_clerk_token():
    """Verify WebSocket connection is rejected with policy violation when token signature is untrusted."""
    client = TestClient(app)
    bad_token = create_test_clerk_token(
        sub="user_2attacker",
        username="attacker",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_attacker_private_key,
    )

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({"type": "auth", "token": bad_token, "tenant_id": TENANT_ALPHA})
            ws.receive_json()


# ──────────────────────────────────────────────
# 6. Agent Investigation under Clerk Context
# ──────────────────────────────────────────────

def test_agent_investigation_under_clerk_context():
    """Verify full agent investigation workflow executes successfully under authenticated Clerk principal."""
    client = TestClient(app)
    clerk_token = create_test_clerk_token(
        sub="user_2analyst",
        username="marcus.vance",
        org_id="org_2secops_alpha",
        org_role="org:analyst",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )
    headers = {"Authorization": f"Bearer {clerk_token}"}

    # Inspect current authenticated principal
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["principal_id"] == "user_2analyst"
    assert me_data["roles"] == ["analyst"]
    assert me_data["tenant_id"] == TENANT_ALPHA

    # Trigger agent investigation
    inv_res = client.post(
        "/api/v1/incident/investigate",
        headers=headers,
        json={"tenant_id": TENANT_ALPHA, "patient_zero_id": "host-0"},
    )
    assert inv_res.status_code == 200
    report = inv_res.json()
    assert report["tenant_id"] == TENANT_ALPHA
    assert report["status"] == "INVESTIGATED"
    assert report["patient_zero_id"] == "host-0"
    assert "attack_paths" in report
    assert "company_brain" in report


# ──────────────────────────────────────────────
# 7. Strict Trust Boundaries & Supply Chain Defense
# ──────────────────────────────────────────────

def test_malicious_or_attacker_controlled_jwks_url_rejected():
    """
    Verify RootMesh NEVER fetches signing keys from an unverified token's issuer or untrusted URL.
    Tokens presenting attacker issuers or forged keys are rejected immediately with 401.
    """
    # Case 1: Token signed with attacker key -> rejected with 401 without querying attacker JWKS
    attacker_token = create_test_clerk_token(
        sub="user_2attacker",
        username="attacker",
        org_id="org_2secops_alpha",
        issuer="https://evil-attacker-host.com",
        private_key=_attacker_private_key,
    )
    with pytest.raises(HTTPException) as exc_info1:
        verify_access_token(attacker_token)
    assert exc_info1.value.status_code == 401

    # Case 2: Token with valid signature but untrusted issuer -> rejected with 401 (invalid issuer)
    attacker_issuer_token = create_test_clerk_token(
        sub="user_2attacker",
        username="attacker",
        org_id="org_2secops_alpha",
        issuer="https://evil-attacker-host.com",
        private_key=_valid_private_key,
    )
    with pytest.raises(HTTPException) as exc_info2:
        verify_access_token(attacker_issuer_token)
    assert exc_info2.value.status_code == 401
    assert "invalid token issuer" in exc_info2.value.detail.lower()


def test_org_slug_matching_rootmesh_with_unapproved_org_id_rejected():
    """
    Verify that an organization slug matching 'rootmesh-*' does NOT grant tenant authorization.
    RootMesh strictly requires an explicitly configured Clerk Organization ID.
    Tokens with unapproved organization IDs are rejected with 403 Forbidden.
    """
    unapproved_token = create_test_clerk_token(
        sub="user_2unapproved",
        username="unapproved.user",
        org_id="org_unapproved_attacker_999",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
        custom_claims={
            "org_slug": "rootmesh-wildcard-bypass",
            "o": {
                "id": "org_unapproved_attacker_999",
                "slg": "rootmesh-wildcard-bypass",
                "rol": "admin",
            },
        },
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(unapproved_token)

    assert exc_info.value.status_code == 403
    assert "not mapped to an authorized rootmesh tenant" in exc_info.value.detail.lower()


def test_missing_production_clerk_configuration_fails_closed(monkeypatch):
    """
    Verify that missing Clerk verification keys, issuer, or org-to-tenant mapping
    fails closed immediately in production mode.
    """
    monkeypatch.setattr(settings, "auth_mode", "prod")
    monkeypatch.setattr(settings, "jwt_secret", "a-cryptographically-secure-production-jwt-secret-key-32chars")
    monkeypatch.setattr(settings, "clerk_pem_public_key", _valid_public_pem)
    monkeypatch.setattr(settings, "clerk_issuer", CLERK_ISSUER)
    monkeypatch.setattr(settings, "clerk_org_to_tenant_map", '{"org_2secops_alpha": "sec_ops_tenant_alpha"}')

    # 1. Missing issuer fails closed with ValueError
    monkeypatch.setattr(settings, "clerk_issuer", None)
    with pytest.raises(ValueError) as exc1:
        settings.validate_production_security()
    assert "CLERK_ISSUER" in str(exc1.value)

    # 2. Missing org mapping fails closed with ValueError
    monkeypatch.setattr(settings, "clerk_issuer", CLERK_ISSUER)
    monkeypatch.setattr(settings, "clerk_org_to_tenant_map", "")
    with pytest.raises(ValueError) as exc2:
        settings.validate_production_security()
    assert "CLERK_ORG_TO_TENANT_MAP" in str(exc2.value)

    # 3. verify_clerk_token fails closed with 500 in production when issuer is missing
    token = create_test_clerk_token(
        sub="user_2valid",
        username="valid.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )
    monkeypatch.setattr(settings, "clerk_issuer", None)
    with pytest.raises(HTTPException) as exc3:
        verify_clerk_token(token)
    assert exc3.value.status_code == 500
    assert "trusted clerk issuer is not configured" in exc3.value.detail.lower()


# ──────────────────────────────────────────────
# 8. Complete Anonymous Access Elimination & Route Protection Verification
# ──────────────────────────────────────────────

def test_anonymous_auth_me_rejected():
    """Verify GET /api/v1/auth/me without Bearer token returns HTTP 401 Unauthorized."""
    client = TestClient(app)
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_anonymous_investigation_rejected():
    """Verify POST /api/v1/incident/investigate without Bearer token returns HTTP 401 Unauthorized."""
    client = TestClient(app)
    res = client.post(
        "/api/v1/incident/investigate",
        json={"tenant_id": TENANT_ALPHA, "patient_zero_id": "host-0"},
    )
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_missing_token_with_auth_mode_dev_rejected(monkeypatch):
    """
    Verify that even with auth_mode='dev', missing Bearer token returns HTTP 401.
    Confirms implicit development-admin authentication fallback is completely eliminated.
    """
    monkeypatch.setattr(settings, "auth_mode", "dev")
    client = TestClient(app)
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_missing_token_with_auth_mode_prod_rejected(monkeypatch):
    """Verify missing Bearer token in production mode returns HTTP 401."""
    monkeypatch.setattr(settings, "auth_mode", "prod")
    client = TestClient(app)
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_legacy_dev_token_bypass_rejected():
    """
    Verify legacy password and dev-token endpoints cannot be used to bypass Clerk.
    Both return HTTP 403 Forbidden when Clerk authentication is active.
    """
    client = TestClient(app)
    res_dev = client.post(
        "/api/v1/auth/dev-token",
        json={"username": "alex.rivera", "tenant_id": TENANT_ALPHA, "roles": ["admin"]},
    )
    assert res_dev.status_code == 403
    assert "disabled when Clerk authentication is active" in res_dev.json()["detail"]

    res_pwd = client.post(
        "/api/v1/auth/token",
        json={"username": "alex.rivera", "secret": "test-dev-credential", "tenant_id": TENANT_ALPHA},
    )
    assert res_pwd.status_code == 403
    assert "disabled when Clerk authentication is active" in res_pwd.json()["detail"]


def test_unauthorized_sensitive_get_endpoints_rejected():
    """Verify sensitive graph and incident GET endpoints unconditionally reject anonymous callers with 401."""
    client = TestClient(app)

    # Topology inventory
    res_topo = client.get(f"/api/v1/threat/topology/{TENANT_ALPHA}")
    assert res_topo.status_code == 401

    # PageRank criticality
    res_pr = client.get(f"/api/v1/threat/pagerank/{TENANT_ALPHA}")
    assert res_pr.status_code == 401

    # Company Brain traversal
    res_cb = client.get(f"/api/v1/incident/company-brain/{TENANT_ALPHA}/host-0")
    assert res_cb.status_code == 401


def test_anonymous_websocket_rejected():
    """Verify WebSocket /ws/threat-stream strictly rejects query parameter tokens and unauthenticated access."""
    client = TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream?token=forbidden_query_token"):
            pass


def test_valid_clerk_authenticated_investigation():
    """Verify valid Clerk-authenticated investigation succeeds and returns real graph analysis."""
    client = TestClient(app)
    token = create_test_clerk_token(
        sub="user_2clerk_investigator",
        username="marcus.vance",
        org_id="org_2secops_alpha",
        org_role="org:admin",
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post(
        "/api/v1/incident/investigate",
        headers=headers,
        json={"tenant_id": TENANT_ALPHA, "patient_zero_id": "host-0"},
    )
    assert res.status_code == 200
    report = res.json()
    assert report["tenant_id"] == TENANT_ALPHA
    assert report["patient_zero_id"] == "host-0"
    assert "incident_id" in report
    assert "attack_paths" in report
    assert "company_brain" in report


def test_cross_tenant_and_role_enforcement_behavior():
    """Verify cross-tenant access is blocked with 403 and responder cannot approve containment."""
    client = TestClient(app)
    alpha_token = create_test_clerk_token(
        sub="user_2cross_tester",
        username="cross.tester",
        org_id="org_2secops_alpha",
        org_role="org:admin",  # maps to responder
        issuer=CLERK_ISSUER,
        private_key=_valid_private_key,
    )
    headers = {"Authorization": f"Bearer {alpha_token}"}

    # 1. Cross-tenant access to Tenant Beta rejected
    res_cross = client.get(f"/api/v1/threat/topology/{TENANT_BETA}", headers=headers)
    assert res_cross.status_code == 403
    assert "Cross-tenant access rejected" in res_cross.json()["detail"]

    # 2. Responder role cannot approve containment (separation of duties)
    res_review = client.post(
        "/api/v1/incident/review",
        headers=headers,
        json={"action_id": "act-unauth-test", "decision": "APPROVE"},
    )
    assert res_review.status_code == 403
    assert "Principal lacks required permission 'containment:approve'" in res_review.json()["detail"]
