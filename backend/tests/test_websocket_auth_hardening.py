"""
RootMesh — WebSocket Authentication Security Hardening Test Suite
Verifies:
1. In-band authentication success over clean WebSocket URL (no query tokens).
2. Rejection of tokens in query parameters (preventing log leakage).
3. Rejection of missing token in authentication payload.
4. Rejection of expired session tokens.
5. Rejection of invalid token signatures.
6. Rejection of cross-tenant subscriptions.
7. Authentication timeout enforcement on initial message.
8. In-band token renewal lifecycle over active connection.
9. Reconnect lifecycle and clean disconnection cleanup without memory/socket leaks.
10. Strict absence of secrets or raw JWTs in server logs.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from app.config import settings
from app.main import app, ws_manager
from app.security.auth import create_test_clerk_token

# Cryptographic test keys
_test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_test_public_pem = _test_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

_attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

from app.db.test_guard import TEST_TENANT_ALPHA, TEST_TENANT_BETA

TENANT_ALPHA = TEST_TENANT_ALPHA
TENANT_BETA = TEST_TENANT_BETA
CLERK_ISSUER = "https://clerk.rootmesh.security"


@pytest.fixture(autouse=True)
def setup_ws_auth_env(monkeypatch):
    """Sets up official Clerk test environment for WebSocket security hardening tests."""
    monkeypatch.setattr(settings, "clerk_pem_public_key", _test_public_pem)
    monkeypatch.setattr(settings, "clerk_issuer", CLERK_ISSUER)
    monkeypatch.setattr(settings, "clerk_authorized_parties", "http://localhost:3000,http://127.0.0.1:3000")
    monkeypatch.setattr(settings, "ws_auth_timeout_seconds", 5.0)
    monkeypatch.setattr(
        settings,
        "clerk_org_to_tenant_map",
        json.dumps({
            "org_2secops_alpha": TENANT_ALPHA,
            "org_2secops_beta": TENANT_BETA,
        }),
    )


def test_websocket_auth_success():
    """Verify in-band authentication succeeds over clean URL without query tokens."""
    client = TestClient(app)
    token = create_test_clerk_token(
        sub="usr_ws_success_01",
        username="alex.rivera",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
    )

    initial_tenant_count = len(ws_manager.tenant_connections.get(TENANT_ALPHA, set()))

    with client.websocket_connect("/ws/threat-stream") as ws:
        # Before authentication: not registered to tenant
        assert len(ws_manager.tenant_connections.get(TENANT_ALPHA, set())) == initial_tenant_count

        # Send in-band authentication message
        ws.send_json({
            "type": "auth",
            "token": token,
            "tenant_id": TENANT_ALPHA,
        })

        auth_ack = ws.receive_json()
        assert auth_ack["type"] == "auth_ok"
        assert auth_ack["tenant_id"] == TENANT_ALPHA
        assert auth_ack["principal_id"] == "usr_ws_success_01"

        # After authentication: registered to tenant
        assert len(ws_manager.tenant_connections[TENANT_ALPHA]) == initial_tenant_count + 1

        # Ping / pong operational check
        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"
        assert pong["tenant_id"] == TENANT_ALPHA


def test_websocket_rejects_query_parameter_token():
    """Verify passing credentials in WebSocket query parameters is strictly forbidden."""
    client = TestClient(app)
    token = create_test_clerk_token(
        sub="usr_ws_query_leak",
        username="leak.tester",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
    )

    # Attempting to connect with token query parameter must be rejected immediately
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws/threat-stream?token={token}&tenant_id={TENANT_ALPHA}"):
            pass


def test_websocket_missing_token_in_auth_message():
    """Verify authentication fails when auth payload does not include token."""
    client = TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({"type": "auth", "tenant_id": TENANT_ALPHA})
            ws.receive_json()


def test_websocket_expired_token_rejected():
    """Verify expired tokens are rejected with policy violation."""
    client = TestClient(app)
    expired_token = create_test_clerk_token(
        sub="usr_ws_expired",
        username="expired.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
        expires_in_seconds=-120,
    )

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({
                "type": "auth",
                "token": expired_token,
                "tenant_id": TENANT_ALPHA,
            })
            ws.receive_json()


def test_websocket_invalid_signature_rejected():
    """Verify tokens signed with untrusted keys are rejected with policy violation."""
    client = TestClient(app)
    untrusted_token = create_test_clerk_token(
        sub="usr_ws_attacker",
        username="attacker.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_attacker_key,
    )

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({
                "type": "auth",
                "token": untrusted_token,
                "tenant_id": TENANT_ALPHA,
            })
            ws.receive_json()


def test_websocket_cross_tenant_access_rejected():
    """Verify token authorized only for Tenant Alpha is rejected when requesting Tenant Beta."""
    client = TestClient(app)
    alpha_token = create_test_clerk_token(
        sub="usr_ws_cross_tenant",
        username="alpha.user",
        org_id="org_2secops_alpha",  # Maps to TENANT_ALPHA
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
    )

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({
                "type": "auth",
                "token": alpha_token,
                "tenant_id": TENANT_BETA,  # Cross-tenant subscription attempt
            })
            ws.receive_json()


def test_websocket_auth_timeout(monkeypatch):
    """Verify connection is closed if client fails to send auth message within timeout."""
    monkeypatch.setattr(settings, "ws_auth_timeout_seconds", 0.2)
    client = TestClient(app)

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws:
            # Client connects but remains idle without sending auth message
            time.sleep(0.3)
            ws.send_json({"type": "ping"})
            ws.receive_json()


def test_websocket_token_renewal_lifecycle():
    """Verify active WebSocket supports in-band token renewal."""
    client = TestClient(app)
    token_v1 = create_test_clerk_token(
        sub="usr_ws_renewal",
        username="renew.analyst",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
        expires_in_seconds=300,
    )
    token_v2 = create_test_clerk_token(
        sub="usr_ws_renewal",
        username="renew.analyst",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
        expires_in_seconds=3600,
    )

    with client.websocket_connect("/ws/threat-stream") as ws:
        # Initial auth
        ws.send_json({"type": "auth", "token": token_v1, "tenant_id": TENANT_ALPHA})
        ack = ws.receive_json()
        assert ack["type"] == "auth_ok"

        # In-band renewal
        ws.send_json({"type": "token_refresh", "token": token_v2})
        renew_ack = ws.receive_json()
        assert renew_ack["type"] == "token_refresh_ok"
        assert renew_ack["tenant_id"] == TENANT_ALPHA

        # Operational health check remains live
        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"


def test_websocket_reconnect_lifecycle_and_clean_disconnect():
    """Verify reconnect lifecycle cleanly cleans up subscribers and prevents socket/state leakage."""
    client = TestClient(app)
    token = create_test_clerk_token(
        sub="usr_ws_reconnect",
        username="reconnect.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
    )

    initial_total = len(ws_manager.active_connections)
    initial_alpha = len(ws_manager.tenant_connections.get(TENANT_ALPHA, set()))

    # Cycle 1: Connect, Authenticate, Disconnect
    with client.websocket_connect("/ws/threat-stream") as ws1:
        ws1.send_json({"type": "auth", "token": token, "tenant_id": TENANT_ALPHA})
        assert ws1.receive_json()["type"] == "auth_ok"
        assert len(ws_manager.active_connections) == initial_total + 1
        assert len(ws_manager.tenant_connections[TENANT_ALPHA]) == initial_alpha + 1

    # Verify complete cleanup
    assert len(ws_manager.active_connections) == initial_total
    assert len(ws_manager.tenant_connections.get(TENANT_ALPHA, set())) == initial_alpha

    # Cycle 2: Reconnect cleanly
    with client.websocket_connect("/ws/threat-stream") as ws2:
        ws2.send_json({"type": "auth", "token": token, "tenant_id": TENANT_ALPHA})
        assert ws2.receive_json()["type"] == "auth_ok"
        assert len(ws_manager.active_connections) == initial_total + 1
        assert len(ws_manager.tenant_connections[TENANT_ALPHA]) == initial_alpha + 1

    # Verify final cleanup
    assert len(ws_manager.active_connections) == initial_total
    assert len(ws_manager.tenant_connections.get(TENANT_ALPHA, set())) == initial_alpha


def test_absence_of_secrets_in_connection_urls_and_logs(caplog):
    """Verify raw JWT tokens and credentials never appear in server connection logs."""
    client = TestClient(app)
    from uuid import uuid4
    secret_marker = f"synthetic-jwt-subject-{uuid4().hex}"
    token = create_test_clerk_token(
        sub=secret_marker,
        username="audit.user",
        org_id="org_2secops_alpha",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
    )

    with caplog.at_level(logging.DEBUG, logger="RootMesh-Backend"):
        with client.websocket_connect("/ws/threat-stream") as ws:
            ws.send_json({"type": "auth", "token": token, "tenant_id": TENANT_ALPHA})
            assert ws.receive_json()["type"] == "auth_ok"

    log_text = caplog.text
    # Raw token string must NEVER appear in logs
    assert token not in log_text, "Security violation: Raw JWT token leaked in logs!"
    assert "Bearer" not in log_text
    # Sanitized diagnostic information must be present
    assert TENANT_ALPHA in log_text
    assert secret_marker in log_text  # principal_id logged for audit trail


def test_frontend_threatstream_handshake_contract():
    """Verify exact frontend-to-backend ThreatStream handshake contract.

    Ensures:
    1. Frontend frame `{"type": "auth", "token": <jwt>, "tenant_id": <tenant>}` produces `auth_ok`.
    2. Response contains expected contract fields: type, tenant_id, principal_id, roles, timestamp.
    3. Cross-tenant subscription attempts fail closed with WS_1008_POLICY_VIOLATION.
    4. Passing JWTs or tenant identifiers in URL query parameters fails closed.
    """
    client = TestClient(app)
    alpha_token = create_test_clerk_token(
        sub="usr_frontend_contract_01",
        username="alex.contract",
        org_id="org_2secops_alpha",
        org_role="org:admin",
        issuer=CLERK_ISSUER,
        private_key=_test_private_key,
    )

    # 1. Clean URL connection and authorized in-band authentication
    with client.websocket_connect("/ws/threat-stream") as ws:
        # Frontend auth frame dispatched by sendWebSocketAuth
        frontend_auth_frame = {
            "type": "auth",
            "token": alpha_token,
            "tenant_id": TENANT_ALPHA,
        }
        ws.send_json(frontend_auth_frame)

        response = ws.receive_json()
        assert response["type"] == "auth_ok", f"Expected 'auth_ok', got {response.get('type')}"
        assert response["tenant_id"] == TENANT_ALPHA
        assert response["principal_id"] == "usr_frontend_contract_01"
        assert "responder" in response["roles"]
        assert isinstance(response["timestamp"], int)

    # 2. Cross-tenant handshake attempt must be rejected and closed
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream") as ws_cross:
            ws_cross.send_json({
                "type": "auth",
                "token": alpha_token,  # Token bound to org_2secops_alpha
                "tenant_id": TENANT_BETA,  # Attempting subscription to TENANT_BETA
            })
            ws_cross.receive_json()

    # 3. Connection with URL query parameters must be rejected immediately
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws/threat-stream?token={alpha_token}&tenant_id={TENANT_ALPHA}"):
            pass


@pytest.mark.asyncio
async def test_websocket_bounded_shutdown_with_active_connections():
    """Verify lifespan shutdown cleanly closes all active WebSocket connections without hanging."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock
    from app.main import lifespan, app
    from app.websocket import ws_manager

    mock_ws = MagicMock()
    mock_ws.close = AsyncMock()
    mock_ws.application_state = MagicMock()

    # Simulate an active connection
    await ws_manager.connect(mock_ws, tenant_id=TENANT_ALPHA)
    assert mock_ws in ws_manager.active_connections

    # Trigger lifespan context exit (simulates server shutdown)
    async with lifespan(app):
        pass

    # Verified: active connection was cleanly closed and deregistered
    mock_ws.close.assert_awaited_once_with(code=1001, reason="Server shutting down")
    assert mock_ws not in ws_manager.active_connections
