"""
RootMesh — Real-Time WebSocket Threat Stream Tests
Tests: WebSocket connection lifecycle, client ack echo, and event payload transport.
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import app


def test_websocket_threat_stream_lifecycle():
    """Verify WebSocket connects, accepts json payload, and receives structured ack."""
    client = TestClient(app)
    with client.websocket_connect("/ws/threat-stream") as ws:
        payload = {"event": "CLIENT_PING", "client": "pytest_integration_suite"}
        ws.send_json(payload)
        ack = ws.receive_json()
        assert ack["ack"] is True
        assert ack["received"]["event"] == "CLIENT_PING"


def test_websocket_broadcast_distribution():
    """Verify WebSocket connection manager handles connected client list."""
    from app.main import ws_manager
    initial_count = len(ws_manager.active_connections)
    client = TestClient(app)
    with client.websocket_connect("/ws/threat-stream"):
        assert len(ws_manager.active_connections) == initial_count + 1
    # After exit, connection count is restored
    assert len(ws_manager.active_connections) == initial_count
