"""
RootMesh — Multi-Tenant Isolation & Security Boundary Tests
Tests: Graph data segregation across tenants, unauthorized tenant rejection (HTTP 403),
and malformed / injection tenant parameter rejection (HTTP 400).
Strictly isolated: Executes against test FalkorDB instance on port 6380 using test graphs.
"""
from __future__ import annotations

import time
import pytest
from starlette.testclient import TestClient

from app.db.falkor_client import db_pool
from app.db.test_guard import TEST_TENANT_ALPHA, TEST_TENANT_BETA, TestDatabaseIsolationError
from app.main import app
from app.security.auth import generate_dev_token

TENANT_ALPHA = TEST_TENANT_ALPHA
TENANT_BETA = TEST_TENANT_BETA


@pytest.fixture(scope="module")
def setup_tenants():
    """Ensure both isolated test tenant graph instances exist on test database."""
    graph_a = db_pool.get_tenant_graph(TENANT_ALPHA)
    graph_b = db_pool.get_tenant_graph(TENANT_BETA)

    # Seed an isolated node in test beta graph
    try:
        graph_b.delete()
    except Exception:
        pass

    graph_b.query("CREATE (:Host {id: 'host-beta-1', name: 'BetaWorkstation', ip: '192.168.1.10'})")
    yield graph_a, graph_b


def test_cross_tenant_data_isolation(setup_tenants):
    """
    Verify complete graph isolation:
    Findings written to tenant alpha must NOT exist in tenant beta.
    """
    graph_a, graph_b = setup_tenants

    # Write finding to alpha with unique ID
    finding_id = f"isolation-test-finding-{int(time.time() * 1000)}"
    graph_a.query(f"""
        MATCH (h:Host {{id: 'host-0'}})
        CREATE (f:Finding {{id: '{finding_id}', text: 'Secret Alpha Data'}})
        CREATE (f)-[:ABOUT]->(h)
    """)

    # Verify finding exists in alpha
    res_a = graph_a.ro_query(f"MATCH (f:Finding {{id: '{finding_id}'}}) RETURN count(f)").result_set
    assert res_a[0][0] == 1, "Finding was not written to tenant alpha"

    # Verify finding DOES NOT exist in beta
    res_b = graph_b.ro_query(f"MATCH (f:Finding {{id: '{finding_id}'}}) RETURN count(f)").result_set
    assert res_b[0][0] == 0, "CRITICAL: Cross-tenant data leak! Tenant Beta can read Tenant Alpha finding"


def test_fail_closed_guard_blocks_persistent_tenant_mutation():
    """
    Verify fail-closed guard prevents any test from mutating live persistent graphs:
    'sec_ops_tenant_alpha' write operations must be blocked with TestDatabaseIsolationError.
    """
    persistent_graph = db_pool.get_tenant_graph("sec_ops_tenant_alpha")
    with pytest.raises(TestDatabaseIsolationError):
        persistent_graph.query("CREATE (:RogueNode {id: 'fail-closed-test'})")

    with pytest.raises(TestDatabaseIsolationError):
        persistent_graph.delete()


def test_tenant_id_injection_protection():
    """Verify malformed or injection tenant IDs raise ValueError in db_pool."""
    with pytest.raises(ValueError):
        db_pool.get_tenant_graph("tenant; DROP GRAPH;")

    with pytest.raises(ValueError):
        db_pool.get_tenant_graph("../../etc/passwd")

    with pytest.raises(ValueError):
        db_pool.get_tenant_graph("invalid@tenant!#")


@pytest.fixture
def client():
    return TestClient(app)


def test_api_rejects_unauthorized_tenant(client):
    """Verify FastAPI rejects unapproved tenant access with HTTP 403 Forbidden for authenticated principal."""
    token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/threat/pagerank/unauthorized_rogue_tenant", headers=headers)
    assert r.status_code == 403
    assert "Access denied" in r.json()["detail"]


def test_api_rejects_malformed_tenant_injection(client):
    """Verify FastAPI rejects malformed tenant format with HTTP 400 Bad Request for authenticated principal."""
    token = generate_dev_token(username="alex.rivera", tenant_id=TENANT_ALPHA, roles=["admin"])
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/threat/pagerank/bad;DROP%20GRAPH", headers=headers)
    assert r.status_code == 400
    assert "Malformed tenant ID format" in r.json()["detail"]
