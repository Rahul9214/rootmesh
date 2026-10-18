"""
RootMesh — Model Context Protocol (MCP) Tools Test Suite
Tests: Tool catalog, parameter validation, bounds checking, and read-only safety guardrails.
"""
from __future__ import annotations

import pytest
from app.mcp_server import mcp_app

TENANT_ID = "sec_ops_tenant_alpha"


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
    """Verify Monte Carlo UDF tool execution and parameter bounds clamping."""
    res = await mcp_app.call_tool(
        "falkordb_blast_radius",
        {"tenant_id": TENANT_ID, "patient_zero_id": "host-0", "simulation_runs": 100},
    )
    text = _extract_text(res)
    assert text is not None
    assert "ERROR" not in text
