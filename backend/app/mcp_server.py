"""
RootMesh — MCP Tool Server (Model Context Protocol)
Exposes FalkorDB tools to external LLM agents (Claude, GPT-4, Cursor)
with strict parameter validation, read-only safety boundaries, and tenant isolation.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict

from mcp.server.mcpserver import MCPServer
from falkordb import FalkorDB

from app.config import settings

logger = logging.getLogger("RootMesh-MCP")

mcp_app = MCPServer(
    name="rootmesh-falkordb-mcp",
    description="RootMesh FalkorDB GraphBLAS Cybersecurity Incident Response MCP Provider",
)

_conn_kwargs: dict = {"host": settings.falkor_host, "port": settings.falkor_port}
if settings.falkor_password:
    _conn_kwargs["password"] = settings.falkor_password

db = FalkorDB(**_conn_kwargs)

MUTATION_PATTERN = re.compile(r"\b(CREATE|SET|DELETE|REMOVE|MERGE|DROP)\b", re.IGNORECASE)


@mcp_app.tool()
def falkordb_execute_cypher(cypher_query: str, tenant_id: str = "sec_ops_tenant_alpha") -> str:
    """
    Executes a read-only Cypher query on a tenant FalkorDB graph and returns structured JSON results.
    Safety boundary: Mutation statements (CREATE, SET, DELETE, REMOVE, MERGE, DROP) are strictly prohibited.
    """
    if not settings.is_valid_tenant(tenant_id):
        return f"ERROR: Invalid or unauthorized tenant identifier: '{tenant_id}'"

    query = cypher_query.strip()
    if not query:
        return "ERROR: cypher_query parameter cannot be empty"

    if MUTATION_PATTERN.search(query):
        return "ERROR: Safety boundary violation: Only read-only queries permitted in falkordb_execute_cypher"

    try:
        graph = db.select_graph(tenant_id)
        res = graph.ro_query(query).result_set
        return str(res)
    except Exception as e:
        return f"ERROR: {e}"


@mcp_app.tool()
def falkordb_save_finding_memory(
    host_id: str,
    finding_text: str,
    severity: str = "HIGH",
    tenant_id: str = "sec_ops_tenant_alpha",
) -> str:
    """
    Saves an incident finding as a (:Finding)-[:ABOUT]->(:Host) node in FalkorDB
    for persistent multi-session agent memory (Track 2).
    """
    if not settings.is_valid_tenant(tenant_id):
        return f"ERROR: Invalid or unauthorized tenant identifier: '{tenant_id}'"

    hid = host_id.strip()
    txt = finding_text.strip()
    sev = severity.strip().upper()

    if not hid or not txt:
        return "ERROR: host_id and finding_text are required"
    if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return "ERROR: severity must be CRITICAL, HIGH, MEDIUM, or LOW"

    cypher = """
    MATCH (h:Host {id: $hid})
    CREATE (f:Finding {
        id:         'find-' + toString(timestamp()),
        text:       $txt,
        severity:   $sev,
        created_at: timestamp()
    })
    CREATE (f)-[:ABOUT]->(h)
    RETURN f.id AS finding_id
    """
    try:
        graph = db.select_graph(tenant_id)
        res = graph.query(cypher, {"hid": hid, "txt": txt, "sev": sev}).result_set
        if not res:
            return f"ERROR: Target host '{hid}' not found"
        return f"Finding created: {res[0][0]}"
    except Exception as e:
        return f"ERROR: {e}"


@mcp_app.tool()
def falkordb_triage_host(host_id: str, tenant_id: str = "sec_ops_tenant_alpha") -> str:
    """
    Resolves a host ID against FalkorDB and returns its metadata
    including EDR status, SMB signing, and firewall state.
    """
    if not settings.is_valid_tenant(tenant_id):
        return f"ERROR: Invalid or unauthorized tenant identifier: '{tenant_id}'"

    hid = host_id.strip()
    if not hid:
        return "ERROR: host_id is required"

    cypher = "MATCH (h:Host {id: $hid}) RETURN h.id, h.name, h.ip, h.edr, h.smb_signing, h.firewall LIMIT 1"
    try:
        graph = db.select_graph(tenant_id)
        res = graph.ro_query(cypher, {"hid": hid}).result_set
        if not res:
            return f"Unknown host: {hid}"
        r = res[0]
        return str({"id": r[0], "name": r[1], "ip": r[2], "edr": r[3], "smb_signing": r[4], "firewall": r[5]})
    except Exception as e:
        return f"ERROR: {e}"


@mcp_app.tool()
def falkordb_blast_radius(
    patient_zero_id: str,
    simulation_runs: int = 500,
    tenant_id: str = "sec_ops_tenant_alpha",
) -> str:
    """
    Executes the Monte Carlo blast_radius JavaScript UDF inside FalkorDB
    to compute stochastic infection propagation probabilities.
    """
    if not settings.is_valid_tenant(tenant_id):
        return f"ERROR: Invalid or unauthorized tenant identifier: '{tenant_id}'"

    pz = patient_zero_id.strip()
    if not pz:
        return "ERROR: patient_zero_id is required"

    try:
        runs = max(1, min(int(simulation_runs), 5000))
    except (ValueError, TypeError):
        runs = 500

    cypher = f"RETURN blast_radius_lib.blast_radius($pz, {runs}) AS result"
    try:
        graph = db.select_graph(tenant_id)
        res = graph.ro_query(cypher, {"pz": pz}).result_set
        if res and res[0]:
            return str(res[0][0])
        return str(res)
    except Exception as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    asyncio.run(mcp_app.run_stdio_async())
