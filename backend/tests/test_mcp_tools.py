"""
RootMesh — Model Context Protocol (MCP) Tools Test Suite
Tests: Tool catalog, parameter validation, bounds checking, and read-only safety guardrails.
"""
from __future__ import annotations

import json
import pytest
from app.db.test_guard import TEST_TENANT_ALPHA
from app.mcp_server import mcp_app

TENANT_ID = TEST_TENANT_ALPHA



def _extract_text(res) -> str:
    """Helper to extract text content from CallToolResult or string."""
    if hasattr(res, "content") and res.content:
        return res.content[0].text
    if hasattr(res, "structured_content") and "result" in res.structured_content:
        return str(res.structured_content["result"])
    return str(res)


@pytest.mark.asyncio
async def test_mcp_list_tools():
    """Verify all 4 MCP tools are declared with schema properties."""
    tools = await mcp_app.list_tools()
    tool_names = [t.name for t in tools]
    assert "falkordb_execute_cypher" in tool_names
    assert "falkordb_save_finding_memory" in tool_names
    assert "falkordb_triage_host" in tool_names
    assert "falkordb_blast_radius" in tool_names


@pytest.mark.asyncio
async def test_mcp_execute_cypher_readonly():
    """Verify read-only query executes successfully."""
    res = await mcp_app.call_tool(
        "falkordb_execute_cypher",
        {"tenant_id": TENANT_ID, "cypher_query": "MATCH (h:Host {id: 'host-0'}) RETURN h.name"},
    )
    text = _extract_text(res)
    assert "Workstation-PatientZero" in text


@pytest.mark.asyncio
async def test_mcp_execute_cypher_blocks_mutation():
    """Verify safety boundary blocks mutation queries (CREATE, DELETE, DROP)."""
    mutation_query = "CREATE (h:Host {id: 'hacked-host'})"
    res = await mcp_app.call_tool(
        "falkordb_execute_cypher",
        {"tenant_id": TENANT_ID, "cypher_query": mutation_query},
    )
    text = _extract_text(res)
    assert "Safety boundary violation" in text


@pytest.mark.asyncio
async def test_mcp_save_finding_memory():
    """Verify finding memory persistence tool."""
    res = await mcp_app.call_tool(
        "falkordb_save_finding_memory",
        {
            "tenant_id": TENANT_ID,
            "host_id": "host-0",
            "finding_text": "MCP test finding entry",
            "severity": "HIGH",
        },
    )
    text = _extract_text(res)
    assert "Finding created: find-" in text


@pytest.mark.asyncio
async def test_mcp_save_finding_validation():
    """Verify finding memory rejects invalid severity or empty parameters."""
    res = await mcp_app.call_tool(
        "falkordb_save_finding_memory",
        {
            "tenant_id": TENANT_ID,
            "host_id": "",
            "finding_text": "",
        },
    )
    assert "ERROR" in _extract_text(res)

    res_sev = await mcp_app.call_tool(
        "falkordb_save_finding_memory",
        {
            "tenant_id": TENANT_ID,
            "host_id": "host-0",
            "finding_text": "Text",
            "severity": "SUPER_CRITICAL_INVALID",
        },
    )
    assert "ERROR" in _extract_text(res_sev)


@pytest.mark.asyncio
async def test_mcp_triage_host():
    """Verify host metadata triage tool."""
    res = await mcp_app.call_tool(
        "falkordb_triage_host",
        {"tenant_id": TENANT_ID, "host_id": "host-0"},
    )
    text = _extract_text(res)
    assert "Workstation-PatientZero" in text
    assert "10.0.1.15" in text


@pytest.mark.asyncio
async def test_mcp_blast_radius():
    """Verify Monte Carlo UDF tool execution, response schema, and distribution counts."""
    runs = 100
    res = await mcp_app.call_tool(
        "falkordb_blast_radius",
        {"tenant_id": TENANT_ID, "patient_zero_id": "host-0", "simulation_runs": runs},
    )
    text = _extract_text(res)
    assert text is not None
    data = json.loads(text) if isinstance(text, str) else text
    assert data.get("status") == "success", f"Expected status 'success', got: {data}"
    assert data.get("patient_zero") == "host-0"
    assert data.get("simulation_runs") == runs
    assert data.get("tenant_id") == TENANT_ID
    infection_dist = data.get("infection_distribution")
    assert isinstance(infection_dist, dict), f"Expected dict for infection_distribution, got {type(infection_dist)}"
    assert len(infection_dist) > 0, "Expected nonempty infection_distribution dictionary"
    for host_name, count in infection_dist.items():
        assert isinstance(host_name, str) and len(host_name) > 0, f"Invalid host name: {host_name}"
        assert isinstance(count, int), f"Infection count must be int, got {type(count)}"
        assert 0 <= count <= runs, f"Count {count} out of bounds [0, {runs}]"
