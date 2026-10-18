"""
RootMesh — Production PyTest Suite
Tests: FalkorDB connectivity, multi-hop traversal, PageRank, MaxFlow, Shortest Path,
Monte Carlo UDF, Finding memory, cross-session recall, containment, and FastAPI contracts.
"""
from __future__ import annotations

import time
import pytest
import requests
from falkordb import FalkorDB

FALKOR_HOST = "localhost"
FALKOR_PORT = 6379
FALKOR_PASSWORD = ""
TENANT_ID = "sec_ops_tenant_alpha"
API_BASE = "http://localhost:8000"
SLA_MAX_MS = 50.0


@pytest.fixture(scope="module")
def falkor_graph():
    kwargs: dict = {"host": FALKOR_HOST, "port": FALKOR_PORT}
    if FALKOR_PASSWORD:
        kwargs["password"] = FALKOR_PASSWORD
    db = FalkorDB(**kwargs)
    yield db.select_graph(TENANT_ID)


# ──────────────────────────────────────────────
# FalkorDB Direct Execution Tests
# ──────────────────────────────────────────────

def test_falkordb_connectivity(falkor_graph):
    """Verify FalkorDB RESP connection and graph instance availability."""
    res = falkor_graph.ro_query("RETURN 1 AS ping").result_set
    assert res[0][0] == 1, "FalkorDB ping failed"


def test_host_nodes_seeded(falkor_graph):
    """Verify patient-zero host exists in the threat graph."""
    res = falkor_graph.ro_query(
        "MATCH (h:Host {id: $id}) RETURN h.name AS name LIMIT 1",
        {"id": "host-0"},
    ).result_set
    assert len(res) == 1, "Patient-zero host-0 not found in graph"
    assert res[0][0] == "Workstation-PatientZero"


def test_cve_vulnerability_links(falkor_graph):
    """Verify CVE vulnerability relationships are present."""
    res = falkor_graph.ro_query("""
        MATCH (h:Host)-[:HAS_VULNERABILITY]->(c:CVE)
        RETURN count(c) AS cve_count
    """).result_set
    assert res[0][0] >= 2, "CVE nodes not linked"


def test_multihop_attack_traversal(falkor_graph):
    """Test variable-length Cypher traversal (*1..4) from patient-zero."""
    cypher = """
    MATCH path = (p:Host {id: 'host-0'})-[:COMMUNICATES|EXPOSED_TO*1..4]->(target:Host)
    RETURN count(target) AS target_count
    """
    result = falkor_graph.ro_query(cypher).result_set
    assert result[0][0] >= 1, "No attack paths found from host-0"


def test_pagerank_algorithm_execution(falkor_graph):
    """Verify native FalkorDB PageRank algorithm returns ranked nodes."""
    cypher = """
    CALL algo.pageRank('Host', 'COMMUNICATES')
    YIELD node, score
    RETURN count(node) AS ranked_nodes
    """
    result = falkor_graph.ro_query(cypher).result_set
    assert result[0][0] > 0, "PageRank returned zero ranked nodes"


def test_maxflow_algorithm_execution(falkor_graph):
    """Verify native FalkorDB algo.maxFlow data egress calculation."""
    cypher = """
    MATCH (source:Host {id: 'host-0'}), (sink:Host {id: 'host-7'})
    CALL algo.maxFlow({
        sourceNodes: [source],
        targetNodes: [sink],
        relationshipTypes: ['COMMUNICATES'],
        capacityProperty: 'bandwidth_mbps'
    })
    YIELD maxFlow
    RETURN maxFlow
    """
    res = falkor_graph.ro_query(cypher).result_set
    assert len(res) == 1
    assert isinstance(res[0][0], (int, float))


def test_shortest_path_execution(falkor_graph):
    """Verify shortest path computation in FalkorDB."""
    cypher = """
    MATCH (source:Host {id: 'host-0'}), (sink:Host {id: 'host-7'})
    WITH shortestPath((source)-[:COMMUNICATES|EXPOSED_TO*]->(sink)) AS path
    RETURN length(path) AS distance, [n IN nodes(path) | n.name] AS p
    """
    res = falkor_graph.ro_query(cypher).result_set
    assert len(res) == 1
    assert res[0][0] >= 1


def test_monte_carlo_udf_execution(falkor_graph):
    """Verify embedded FalkorDB JavaScript UDF 'blast_radius' execution."""
    cypher = "RETURN blast_radius_lib.blast_radius('host-0', 100) AS result"
    res = falkor_graph.ro_query(cypher).result_set
    assert len(res) == 1
    assert res[0][0] is not None


def test_finding_memory_persistence_and_cross_session_recall(falkor_graph):
    """Verify episodic finding memory persistence and cross-session recall (Track 2)."""
    fid = f"test-session-finding-{int(time.time() * 1000)}"
    write_cypher = f"""
    MATCH (h:Host {{id: 'host-0'}})
    CREATE (f:Finding {{
        id: '{fid}',
        text: 'RootMesh episodic memory cross-session audit test',
        severity: 'CRITICAL',
        session_id: 'session-audit-2026',
        at: timestamp()
    }})
    CREATE (f)-[:ABOUT]->(h)
    RETURN f.id AS fid
    """
    res = falkor_graph.query(write_cypher).result_set
    assert res[0][0] == fid

    # Cross-session recall query
    recall = falkor_graph.ro_query(f"""
        MATCH (f:Finding {{id: '{fid}'}})-[:ABOUT]->(h:Host)
        RETURN f.text AS txt, h.id AS hid, f.session_id AS sid
    """).result_set
    assert len(recall) == 1
    assert recall[0][0] == "RootMesh episodic memory cross-session audit test"
    assert recall[0][1] == "host-0"
    assert recall[0][2] == "session-audit-2026"


def test_oncall_owner_resolution(falkor_graph):
    """Verify Track 3 on-call owner graph is queryable."""
    cypher = """
    MATCH (p:Person)-[:ONCALL_FOR]->(t:Team)
    RETURN p.name AS responder, t.name AS team LIMIT 1
    """
    result = falkor_graph.ro_query(cypher).result_set
    assert len(result) >= 1, "No on-call owner found"
    assert result[0][0] == "Alex Rivera"


# ──────────────────────────────────────────────
# FastAPI Integration Tests
# ──────────────────────────────────────────────

def test_fastapi_health():
    """Validate FastAPI health endpoint."""
    try:
        r = requests.get(f"{API_BASE}/health", timeout=5)
        assert r.status_code == 200
        assert r.json()["status"] == "operational"
        assert r.json()["product"] == "RootMesh"
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_traversal_api():
    """Validate traversal API endpoint SLA (<50ms)."""
    payload = {
        "tenant_id": TENANT_ID,
        "patient_zero_id": "host-0",
        "max_hops": 4,
    }
    try:
        r = requests.post(f"{API_BASE}/api/v1/threat/traverse", json=payload, timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "execution_time_ms" in data
        assert data["execution_time_ms"] < SLA_MAX_MS, f"SLA breach: {data['execution_time_ms']}ms"
        assert data["target_count"] >= 1
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_pagerank_api():
    """Validate PageRank endpoint returns ranked hosts."""
    try:
        r = requests.get(f"{API_BASE}/api/v1/threat/pagerank/{TENANT_ID}", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 1
        assert "score" in data[0]
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_egress_maxflow_api():
    """Validate MaxFlow egress calculation API."""
    payload = {
        "tenant_id": TENANT_ID,
        "source_id": "host-0",
        "sink_id": "host-7",
    }
    try:
        r = requests.post(f"{API_BASE}/api/v1/threat/egress", json=payload, timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "max_egress_mbps" in data
        assert data["execution_time_ms"] < SLA_MAX_MS
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_shortest_path_api():
    """Validate shortest path API endpoint."""
    payload = {
        "tenant_id": TENANT_ID,
        "source_id": "host-0",
        "target_id": "host-7",
    }
    try:
        r = requests.post(f"{API_BASE}/api/v1/threat/shortest-path", json=payload, timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "distance" in data
        assert "path" in data
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_topology_api():
    """Validate network topology inventory endpoint."""
    try:
        r = requests.get(f"{API_BASE}/api/v1/threat/topology/{TENANT_ID}", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 8
        assert data[0]["id"] == "host-0"
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_containment_api():
    """Validate graph-level containment endpoint and explicit simulation distinction."""
    payload = {
        "tenant_id": TENANT_ID,
        "host_id": "host-0",
    }
    try:
        r = requests.post(f"{API_BASE}/api/v1/threat/contain", json=payload, timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "CONTAINED"
        assert data["containment_type"] == "GRAPH_TOPOLOGY_SIMULATION"
        assert "Physical hardware firewall rule enforcement requires authorized appliance connector" in data["enforcement_note"]
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")


def test_fastapi_finding_memory_api():
    """Validate finding memory persistence via API."""
    payload = {
        "tenant_id": TENANT_ID,
        "host_id": "host-0",
        "text": "RootMesh API integration test finding",
        "severity": "HIGH",
        "session_id": "pytest-session",
    }
    try:
        r = requests.post(f"{API_BASE}/api/v1/threat/memory/finding", json=payload, timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "finding_id" in data
    except requests.exceptions.ConnectionError:
        pytest.skip("FastAPI server not running")
