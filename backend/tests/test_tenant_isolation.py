"""
RootMesh — Multi-Tenant Isolation & Security Boundary Tests
Tests: Graph data segregation across tenants, unauthorized tenant rejection (HTTP 403),
and malformed / injection tenant parameter rejection (HTTP 400).
"""
from __future__ import annotations

import pytest
import requests
import time
from app.db.falkor_client import db_pool

API_BASE = "http://localhost:8000"
TENANT_ALPHA = "sec_ops_tenant_alpha"
TENANT_BETA = "sec_ops_tenant_beta"


@pytest.fixture(scope="module")
def setup_tenants():
    """Ensure both tenant alpha and tenant beta graph instances exist."""
    graph_a = db_pool.get_tenant_graph(TENANT_ALPHA)
    graph_b = db_pool.get_tenant_graph(TENANT_BETA)

    # Seed an isolated node in beta
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


def test_tenant_id_injection_protection():
    """Verify malformed or injection tenant IDs raise ValueError in db_pool."""
    with pytest.raises(ValueError):
        db_pool.get_tenant_graph("tenant; DROP GRAPH;")

    with pytest.raises(ValueError):
        db_pool.get_tenant_graph("../../etc/passwd")

    with pytest.raises(ValueError):
        db_pool.get_tenant_graph("invalid@tenant!#")


def test_api_rejects_unauthorized_tenant():
    """Verify FastAPI rejects unapproved tenant access with HTTP 403 Forbidden."""
    try:
        r = requests.get(f"{API_BASE}/api/v1/threat/pagerank/unauthorized_rogue_tenant", timeout=5)
        assert r.status_code == 403
        assert "Access denied" in r.json()["detail"]
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_api_rejects_malformed_tenant_injection():
    """Verify FastAPI rejects malformed tenant format with HTTP 400 Bad Request."""
    try:
        r = requests.get(f"{API_BASE}/api/v1/threat/pagerank/bad;DROP%20GRAPH", timeout=5)
        assert r.status_code == 400
        assert "Malformed tenant ID format" in r.json()["detail"]
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")
