"""
RootMesh — Real-Time WebSocket Threat Stream Tests
Tests: WebSocket connection lifecycle, client ack echo, and event payload transport.
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import app


def test_websocket_threat_stream_lifecycle():
    """Verify WebSocket connects, accepts json payload, and receives structured ack under in-band authenticated token."""
    client = TestClient(app)
    from app.security.auth import generate_dev_token
    token = generate_dev_token(username="alex.rivera", tenant_id="sec_ops_tenant_alpha", roles=["admin"])
    with client.websocket_connect("/ws/threat-stream") as ws:
        # In-band message authentication
        ws.send_json({"type": "auth", "token": token, "tenant_id": "sec_ops_tenant_alpha"})
        auth_ack = ws.receive_json()
        assert auth_ack["type"] == "auth_ok"
        assert auth_ack["tenant_id"] == "sec_ops_tenant_alpha"

        payload = {"event": "CLIENT_PING", "client": "pytest_integration_suite"}
        ws.send_json(payload)
        ack = ws.receive_json()
        assert ack["ack"] is True
        assert ack["received"]["event"] == "CLIENT_PING"


def test_websocket_broadcast_distribution():
    """Verify WebSocket connection manager handles connected client list strictly after in-band authentication."""
    from app.main import ws_manager
    from app.security.auth import generate_dev_token
    token = generate_dev_token(username="alex.rivera", tenant_id="sec_ops_tenant_alpha", roles=["admin"])
    initial_count = len(ws_manager.active_connections)
    client = TestClient(app)
    with client.websocket_connect("/ws/threat-stream") as ws:
        # Unauthenticated: connection must NOT be registered in active_connections
        assert len(ws_manager.active_connections) == initial_count
        # Perform in-band authentication
        ws.send_json({"type": "auth", "token": token, "tenant_id": "sec_ops_tenant_alpha"})
        auth_ack = ws.receive_json()
        assert auth_ack["type"] == "auth_ok"
        assert len(ws_manager.active_connections) == initial_count + 1
    # After exit, connection count is restored
    assert len(ws_manager.active_connections) == initial_count
