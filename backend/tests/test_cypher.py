"""
RootMesh — Cypher Query Library Unit Tests
Tests: Query syntax, parameter validation, shortest path, and multi-tenant graph isolation.
"""
from __future__ import annotations

import pytest
from app.db.falkor_client import db_pool
from app.db import queries

TENANT_ID = "sec_ops_tenant_alpha"


@pytest.fixture(scope="module")
def graph():
    return db_pool.get_tenant_graph(TENANT_ID)


def test_multi_hop_traversal_parameterized(graph):
    """Verify parameterized multi-hop query syntax and return schema."""
    cypher = queries.MULTI_HOP_TRAVERSAL.replace("{max_hops}", "3")
    res = graph.ro_query(cypher, {"patient_zero_id": "host-0"}).result_set
    assert len(res) > 0
    # Each row: [target_name, target_ip, hops, full_path]
    first_path = res[0]
    assert len(first_path) == 4
    assert first_path[2] >= 1  # hops


def test_shortest_path_parameterized(graph):
    """Verify parameterized shortest path query returns path list and distance."""
    res = graph.ro_query(
        queries.SHORTEST_ATTACK_PATH,
        {"source_id": "host-0", "target_id": "host-7"},
    ).result_set
    assert len(res) == 1
    assert isinstance(res[0][0], list)
    assert res[0][1] >= 1


def test_pagerank_query_schema(graph):
    """Verify algo.pageRank Cypher query execution."""
    res = graph.ro_query(queries.PAGE_RANK_ASSETS).result_set
    assert len(res) > 0
    for row in res:
        assert isinstance(row[0], str)  # host_name
        assert isinstance(row[2], float)  # score


def test_finding_memory_cypher(graph):
    """Verify finding creation and recall Cypher queries."""
    res = graph.query(
        queries.PERSIST_FINDING,
        {
            "host_id": "host-2",
            "text": "Cypher unit test finding entry",
            "severity": "MEDIUM",
            "session_id": "cypher-test-session",
            "confidence": 0.88,
        },
    ).result_set
    assert len(res) == 1
    finding_id = res[0][0]
    assert finding_id.startswith("find-")

    # Verify recall query returns it
    recall = graph.ro_query(queries.RECALL_FINDINGS, {"host_id": "host-2"}).result_set
    assert len(recall) >= 1
    assert recall[0][1] == "Cypher unit test finding entry"


def test_host_exists_cypher(graph):
    """Verify host existence check returns metadata columns."""
    res = graph.ro_query(queries.HOST_EXISTS, {"host_id": "host-0"}).result_set
    assert len(res) == 1
    assert res[0][0] == "host-0"
    assert res[0][1] == "Workstation-PatientZero"
