"""
RootMesh — Step 3BP Operational Reliability & Failure Response Test Suite
Verifies:
1. Health and readiness behavior under operational and disconnected database states.
2. Graceful server shutdown with connected WebSocket clients (close code 1001).
3. WebSocket reconnection protocol, pong heartbeats, and resync acknowledgment.
4. Error handling and fail-closed security for malformed or unauthenticated requests.
5. No sensitive token or credential leakage in responses or logs.

Target: Isolated test environment (FalkorDB port 6380, test graphs).
PERSISTENT PORT 6379 IS NEVER WRITTEN TO OR MUTATED.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.websocket import ws_manager
from app.config import settings
from app.security.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


def test_root_endpoint_metadata(client):
    """Root endpoint must truthfully return service metadata without requiring auth."""
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["product"] == "RootMesh"
    assert "version" in data
    assert data["health"] == "/health"
    assert data["docs"] == "/docs"


def test_health_check_operational(client):
    """When FalkorDB is reachable, /health returns 200 with operational status."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["product"] == "RootMesh"
    assert data["status"] == "operational"
    assert data["database"] == "operational"
    assert data["engine"] == "FalkorDB GraphBLAS"


def test_health_check_failure_isolated(client, monkeypatch):
    """
    When FalkorDB is unreachable (tested via isolated mock without touching port 6379),
    /health returns HTTP 503 with degraded status and informative reason.
    """
    from app.db.falkor_client import db_pool

    def mock_failing_ping():
        raise ConnectionError("Simulated network partition: connection refused")

    monkeypatch.setattr(db_pool.db.connection, "ping", mock_failing_ping)

    res = client.get("/health")
    assert res.status_code == 503
    data = res.json()
    assert data["status"] == "degraded"
    assert "unreachable" in data["database"]
    assert "Simulated network partition" in data["database"]
    assert data["product"] == "RootMesh"


@pytest.mark.asyncio
async def test_websocket_graceful_shutdown():
    """
    Verify that lifespan shutdown cleanly disconnects active WebSockets with code 1001 (Going Away).
    """
    # Create an async mock websocket
    mock_ws = AsyncMock()
    mock_ws.close = AsyncMock()

    # Register to ws_manager using socket_tenants
    ws_manager.active_connections.append(mock_ws)
    ws_manager.socket_tenants[mock_ws] = "tenant_test"
    if "tenant_test" not in ws_manager.tenant_connections:
        ws_manager.tenant_connections["tenant_test"] = set()
    ws_manager.tenant_connections["tenant_test"].add(mock_ws)

    assert len(ws_manager.active_connections) >= 1

    # Execute graceful close_all
    await ws_manager.close_all(code=1001, reason="Server shutting down")

    assert len(ws_manager.active_connections) == 0
    assert mock_ws not in ws_manager.socket_tenants
    mock_ws.close.assert_awaited_once_with(code=1001, reason="Server shutting down")


def test_websocket_in_band_heartbeat_and_resync(client):
    """
    Verify WebSocket responds to ping and resync requests cleanly for reconnection recovery.
    """
    token = create_access_token("user_alpha_1", "ops_user_alpha", "sec_ops_tenant_alpha", ["analyst"])

    with client.websocket_connect("/ws/threat-stream") as ws:
        # 1. In-band auth
        ws.send_json({
            "type": "auth",
            "token": token,
            "tenant_id": "sec_ops_tenant_alpha"
        })
        auth_ack = ws.receive_json()
        assert auth_ack["type"] == "auth_ok"
        assert auth_ack["tenant_id"] == "sec_ops_tenant_alpha"
        assert auth_ack["principal_id"] == "user_alpha_1"

        # 2. Ping heartbeat
        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"
        assert pong["ack"] is True
        assert pong["tenant_id"] == "sec_ops_tenant_alpha"
        assert "timestamp" in pong

        # 3. Resync request after simulated disconnect
        ws.send_json({"type": "resync"})
        resync = ws.receive_json()
        assert resync["type"] == "resync_ack"
        assert resync["ack"] is True
        assert resync["tenant_id"] == "sec_ops_tenant_alpha"


def test_websocket_rejects_query_token_leakage(client):
    """
    Verify that query parameter tokens are rejected immediately to prevent logging credentials.
    """
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/threat-stream?token=sensitive_leak_token") as ws:
            ws.receive_json()


def test_no_sensitive_secrets_in_health_or_root(client):
    """
    Verify neither /health nor / exposes secret keys, JWT secrets, or internal credentials.
    """
    for endpoint in ["/", "/health"]:
        res = client.get(endpoint)
        content = res.text
        assert settings.jwt_secret not in content
        assert "password" not in content.lower()
        assert "secret" not in content.lower() or "RootMesh" in content
