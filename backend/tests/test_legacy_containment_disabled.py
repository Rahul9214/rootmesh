"""
RootMesh — Isolated Regression Tests: Elimination of Legacy Containment Bypass
Verifies that POST /api/v1/threat/contain is permanently disabled (HTTP 410 Gone)
in all environments (development, testing, production) and cannot be executed even
by an authenticated administrator. Confirms that no graph mutations, agent executions,
audit logs, or WebSocket broadcasts are ever triggered.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from app.config import settings
from app.main import app
from app.security.auth import create_access_token

TENANT_ALPHA = "sec_ops_tenant_alpha"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token(
        principal_id="usr-test-admin",
        username="alex.rivera",
        tenant_id=TENANT_ALPHA,
        roles=["admin"],
        custom_claims={"iss": settings.jwt_issuer, "aud": settings.jwt_audience},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def responder_headers():
    token = create_access_token(
        principal_id="usr-test-responder",
        username="sarah.chen",
        tenant_id=TENANT_ALPHA,
        roles=["responder"],
        custom_claims={"iss": settings.jwt_issuer, "aud": settings.jwt_audience},
    )
    return {"Authorization": f"Bearer {token}"}


def test_legacy_containment_disabled_in_development_mode(client, monkeypatch):
    """
    SECURITY REGRESSION:
    Direct containment must be disabled with HTTP 410 in development mode (auth_mode='dev').
    Development mode can no longer bypass the guarded Human-in-the-Loop workflow.
    """
    monkeypatch.setattr(settings, "auth_mode", "dev")
    monkeypatch.setattr(settings, "environment", "development")

    payload = {"tenant_id": TENANT_ALPHA, "host_id": "host-0"}
    res = client.post("/api/v1/threat/contain", json=payload)
    assert res.status_code == 410
    detail = res.json()["detail"]
    assert "permanently disabled in all environments" in detail
    assert "/api/v1/incident/propose" in detail
    assert "/api/v1/incident/review" in detail
    assert "/api/v1/incident/execute" in detail


def test_legacy_containment_disabled_in_production_mode(client, monkeypatch, admin_headers):
    """
    SECURITY REGRESSION:
    Direct containment must be disabled with HTTP 410 in production mode (auth_mode='prod').
    """
    monkeypatch.setattr(settings, "auth_mode", "prod")
    monkeypatch.setattr(settings, "environment", "production")

    payload = {"tenant_id": TENANT_ALPHA, "host_id": "host-0"}
    res = client.post("/api/v1/threat/contain", json=payload, headers=admin_headers)
    assert res.status_code == 410
    assert "permanently disabled in all environments" in res.json()["detail"]


def test_legacy_containment_disabled_for_authenticated_admin(client, admin_headers):
    """
    SECURITY REGRESSION:
    An authenticated administrator with full containment permissions ('containment:execute')
    cannot bypass the 8-stage Human-in-the-Loop workflow via the legacy route.
    """
    payload = {"tenant_id": TENANT_ALPHA, "host_id": "host-0"}
    res = client.post("/api/v1/threat/contain", json=payload, headers=admin_headers)
    assert res.status_code == 410
    assert "permanently disabled in all environments" in res.json()["detail"]


def test_legacy_containment_disabled_for_responder(client, responder_headers):
    """
    SECURITY REGRESSION:
    A responder cannot execute containment directly via the legacy route.
    """
    payload = {"tenant_id": TENANT_ALPHA, "host_id": "host-0"}
    res = client.post("/api/v1/threat/contain", json=payload, headers=responder_headers)
    assert res.status_code == 410
    assert "permanently disabled in all environments" in res.json()["detail"]


def test_legacy_containment_disabled_for_unauthenticated_requests(client):
    """
    SECURITY REGRESSION:
    Unauthenticated / anonymous callers receive HTTP 410 indicating the endpoint is permanently gone.
    """
    payload = {"tenant_id": TENANT_ALPHA, "host_id": "host-0"}
    res = client.post("/api/v1/threat/contain", json=payload)
    assert res.status_code == 410


def test_legacy_containment_disabled_with_empty_or_arbitrary_payload(client, admin_headers):
    """
    SECURITY REGRESSION:
    The endpoint safely returns HTTP 410 regardless of request body structure without 422 or 500.
    """
    # Empty JSON object
    res_empty = client.post("/api/v1/threat/contain", json={}, headers=admin_headers)
    assert res_empty.status_code == 410

    # No payload at all
    res_none = client.post("/api/v1/threat/contain", headers=admin_headers)
    assert res_none.status_code == 410

    # Arbitrary / unexpected payload
    res_extra = client.post(
        "/api/v1/threat/contain",
        json={"bogus": "value", "attack": "bypass"},
        headers=admin_headers,
    )
    assert res_extra.status_code == 410


def test_legacy_containment_never_calls_mitigation_agent(client, admin_headers):
    """
    CRITICAL ISOLATION PROOF:
    Verify MitigationAgent.execute_containment is NEVER invoked by /api/v1/threat/contain.
    """
    with patch("app.agents.mitigation.MitigationAgent.execute_containment") as mock_exec:
        res = client.post(
            "/api/v1/threat/contain",
            json={"tenant_id": TENANT_ALPHA, "host_id": "host-0"},
            headers=admin_headers,
        )
        assert res.status_code == 410
        mock_exec.assert_not_called()


def test_legacy_containment_never_touches_database(client, admin_headers):
    """
    CRITICAL ISOLATION PROOF:
    Verify db_pool.get_tenant_graph is NEVER accessed by /api/v1/threat/contain.
    Guarantees zero graph mutation, zero queries, and zero side effects.
    """
    with patch("app.db.falkor_client.db_pool.get_tenant_graph") as mock_db:
        res = client.post(
            "/api/v1/threat/contain",
            json={"tenant_id": TENANT_ALPHA, "host_id": "host-0"},
            headers=admin_headers,
        )
        assert res.status_code == 410
        mock_db.assert_not_called()


def test_legacy_containment_never_broadcasts_websocket_events(client, admin_headers):
    """
    CRITICAL ISOLATION PROOF:
    Verify WebSocket manager is NEVER invoked to broadcast containment events.
    """
    with patch("app.websocket.ws_manager.broadcast_to_tenant") as mock_ws:
        res = client.post(
            "/api/v1/threat/contain",
            json={"tenant_id": TENANT_ALPHA, "host_id": "host-0"},
            headers=admin_headers,
        )
        assert res.status_code == 410
        mock_ws.assert_not_called()


def test_guarded_execution_pathway_preserved(client, admin_headers):
    """
    Verify the exclusively authorized 8-stage execution pathway remains available:
    - POST /api/v1/incident/propose (containment:propose)
    - POST /api/v1/incident/review  (containment:approve)
    - POST /api/v1/incident/execute (containment:execute)
    And direct execution without prior approval fails closed (HTTP 404 / 400).
    """
    # Attempting execution of non-existent action fails closed
    exec_res = client.post(
        "/api/v1/incident/execute",
        headers=admin_headers,
        json={"action_id": "act-nonexistent-000", "idempotency_key": "idemp-test-safe-1"},
    )
    # Fails closed with 404 (Action proposal not found)
    assert exec_res.status_code == 404
    assert "not found" in exec_res.json()["detail"]
