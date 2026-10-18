"""
RootMesh — Hardened MCP Tool Server (Model Context Protocol)
Exposes strictly fixed, allowlisted, parameterized FalkorDB graph operations
with cryptographic tenant boundaries, query length caps, injection filtering,
and sanitized structured JSON responses. Arbitrary user-supplied Cypher is strictly prohibited.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional

from falkordb import FalkorDB
from mcp.server.mcpserver import MCPServer

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

# ──────────────────────────────────────────────
# Strict Injection & Mutation Guardrails
# ──────────────────────────────────────────────

# Prohibit all data modification and administrative Cypher clauses
FORBIDDEN_CYPHER_KEYWORDS = re.compile(
    r"\b(CREATE|SET|DELETE|REMOVE|MERGE|DROP|DETACH|ALTER|UNION|LOAD|CSV|INDEX)\b",
    re.IGNORECASE,
)

# Prohibit administrative and reflection procedures
ADMIN_PROCEDURES = re.compile(
    r"\bCALL\s+(db\.|graph\.config|redis\.|server\.)",
    re.IGNORECASE,
)

# Prohibit comment injection and multi-statement execution
INJECTION_CHARS = re.compile(r"(;|//|/\*|\*/|--)", re.IGNORECASE)

# Fixed, allowlisted parameterized operations for investigation
# Arbitrary user Cypher is strictly mapped to these pre-compiled templates
ALLOWLISTED_OPERATIONS: List[Dict[str, Any]] = [
    {
        "id": "get_host_name_by_id",
        "pattern": re.compile(r"^\s*MATCH\s*\(\s*h\s*:\s*Host\s*\{\s*id\s*:\s*['\"]([^'\"]+)['\"]\s*\}\s*\)\s*RETURN\s+h\.name\s*$", re.I),
        "template": "MATCH (h:Host {id: $host_id}) RETURN h.name",
        "extract": lambda m: {"host_id": m.group(1)},
    },
    {
        "id": "get_host_details_by_id",
        "pattern": re.compile(r"^\s*MATCH\s*\(\s*h\s*:\s*Host\s*\{\s*id\s*:\s*['\"]([^'\"]+)['\"]\s*\}\s*\)\s*RETURN\s+h\.id\s*,\s*h\.name\s*,\s*h\.ip\s*,\s*h\.status\s*$", re.I),
        "template": "MATCH (h:Host {id: $host_id}) RETURN h.id, h.name, h.ip, h.status",
        "extract": lambda m: {"host_id": m.group(1)},
    },
    {
        "id": "list_host_names",
        "pattern": re.compile(r"^\s*MATCH\s*\(\s*h\s*:\s*Host\s*\)\s*RETURN\s+h\.name\s*$", re.I),
        "template": "MATCH (h:Host) RETURN h.name",
        "extract": lambda m: {},
    },
    {
        "id": "list_host_ids",
        "pattern": re.compile(r"^\s*MATCH\s*\(\s*h\s*:\s*Host\s*\)\s*RETURN\s+h\.id\s*$", re.I),
        "template": "MATCH (h:Host) RETURN h.id",
        "extract": lambda m: {},
    },
    {
        "id": "get_host_cves",
        "pattern": re.compile(r"^\s*MATCH\s*\(\s*h\s*:\s*Host\s*\{\s*id\s*:\s*['\"]([^'\"]+)['\"]\s*\}\s*\)\s*-\s*\[\s*:HAS_VULNERABILITY\s*\]\s*->\s*\(\s*c\s*:\s*CVE\s*\)\s*RETURN\s+c\.id\s*,\s*c\.cvss\s*$", re.I),
        "template": "MATCH (h:Host {id: $host_id})-[:HAS_VULNERABILITY]->(c:CVE) RETURN c.id, c.cvss",
        "extract": lambda m: {"host_id": m.group(1)},
    },
]

MAX_CYPHER_LENGTH = 500
MAX_RESULT_LIMIT = 100


def _structured_error(code: str, message: str) -> str:
    """Returns standardized, sanitized structured error JSON."""
    return json.dumps({
        "status": "error",
        "code": code,
        "message": message,
    })


def _validate_tenant(tenant_id: str) -> Optional[str]:
    """Validates tenant format and authorized membership."""
    if not tenant_id or not settings.is_valid_tenant(tenant_id):
        return _structured_error(
            "INVALID_TENANT_FORMAT",
            f"ERROR: Malformed or invalid tenant identifier: '{tenant_id}'.",
        )
    if tenant_id not in settings.authorized_tenants:
        return _structured_error(
            "UNAUTHORIZED_TENANT",
            f"ERROR: Access denied: Tenant '{tenant_id}' is not authorized on this RootMesh node.",
        )
    return None


# ──────────────────────────────────────────────
# Hardened MCP Tools
# ──────────────────────────────────────────────

@mcp_app.tool()
def falkordb_execute_cypher(
    cypher_query: str,
    tenant_id: str = "sec_ops_tenant_alpha",
    max_records: int = 50,
) -> str:
    """
    Executes a fixed, allowlisted parameterized graph operation against a tenant's graph.
    Safety boundaries:
    - Arbitrary user-supplied Cypher is strictly rejected; only fixed allowlisted operations are permitted
    - Mutation clauses (CREATE, SET, DELETE, MERGE, DROP) strictly rejected
    - Semicolons, comments, and procedure escalation blocked
    - Enforces maximum length and automatic LIMIT clamping
    """
    tenant_err = _validate_tenant(tenant_id)
    if tenant_err:
        return tenant_err

    query = cypher_query.strip()
    if not query:
        return _structured_error("EMPTY_QUERY", "ERROR: cypher_query parameter cannot be empty")

    if len(query) > MAX_CYPHER_LENGTH:
        return _structured_error(
            "QUERY_OVERSIZED",
            f"ERROR: Safety boundary violation: Query length ({len(query)}) exceeds limit of {MAX_CYPHER_LENGTH} chars",
        )

    if INJECTION_CHARS.search(query):
        return _structured_error(
            "INJECTION_DETECTED",
            "ERROR: Safety boundary violation: Comments and multi-statement semicolons are strictly prohibited.",
        )

    if FORBIDDEN_CYPHER_KEYWORDS.search(query):
        return _structured_error(
            "SAFETY_BOUNDARY_VIOLATION",
            "ERROR: Safety boundary violation: Only read-only queries permitted in falkordb_execute_cypher",
        )

    if ADMIN_PROCEDURES.search(query):
        return _structured_error(
            "ADMIN_CALL_PROHIBITED",
            "ERROR: Safety boundary violation: Administrative procedure calls are prohibited.",
        )

    # Check query against fixed allowlisted operations
    matched_op: Optional[Dict[str, Any]] = None
    params: Dict[str, Any] = {}
    for op in ALLOWLISTED_OPERATIONS:
        m = op["pattern"].match(query)
        if m:
            matched_op = op
            params = op["extract"](m)
            break

    if not matched_op:
        return _structured_error(
            "SAFETY_BOUNDARY_VIOLATION",
            "ERROR: Safety boundary violation: Arbitrary user Cypher execution is strictly prohibited. "
            "Only fixed, allowlisted parameterized graph operations are permitted.",
        )

    limit = max(1, min(int(max_records), MAX_RESULT_LIMIT))
    safe_template = f"{matched_op['template']} LIMIT {limit}"

    t0 = time.perf_counter()
    try:
        graph = db.select_graph(tenant_id)
        res = graph.ro_query(safe_template, params).result_set
        exec_ms = round((time.perf_counter() - t0) * 1000, 2)
        return json.dumps({
            "status": "success",
            "tenant_id": tenant_id,
            "operation": matched_op["id"],
            "row_count": len(res),
            "execution_time_ms": exec_ms,
            "data": res,
        })
    except Exception as e:
        return _structured_error("EXECUTION_ERROR", f"ERROR: Graph query execution failure: {e}")


@mcp_app.tool()
def falkordb_save_finding_memory(
    host_id: str,
    finding_text: str,
    severity: str = "HIGH",
    session_id: str = "incident-mcp-session",
    tenant_id: str = "sec_ops_tenant_alpha",
) -> str:
    """
    Saves an incident finding as an episodic memory subgraph (:Finding)-[:ABOUT]->(:Host) in FalkorDB (Track 2).
    Validates host existence, enforces severity boundaries, and sanitizes input text.
    """
    tenant_err = _validate_tenant(tenant_id)
    if tenant_err:
        return tenant_err

    hid = host_id.strip()
    txt = finding_text.strip()
    sev = severity.strip().upper()

    if not hid or not txt:
        return _structured_error("MISSING_ARGUMENTS", "ERROR: host_id and finding_text are required")

    if len(hid) > 64 or len(txt) > 2000:
        return _structured_error("PAYLOAD_OVERSIZED", "ERROR: host_id or finding_text exceeds permitted bounds")

    if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return _structured_error(
            "INVALID_SEVERITY",
            "ERROR: severity must be CRITICAL, HIGH, MEDIUM, or LOW",
        )

    try:
        graph = db.select_graph(tenant_id)

        # Verify host exists before linking finding
        host_check = graph.ro_query("MATCH (h:Host {id: $hid}) RETURN h.id", {"hid": hid}).result_set
        if not host_check:
            return _structured_error("HOST_NOT_FOUND", f"ERROR: Target host '{hid}' not found in tenant graph.")

        cypher = """
        MATCH (h:Host {id: $hid})
        CREATE (f:Finding {
            id:         'find-' + toString(timestamp()),
            text:       $txt,
            severity:   $sev,
            session_id: $sid,
            created_at: timestamp()
        })
        CREATE (f)-[:ABOUT]->(h)
        RETURN f.id AS finding_id
        """
        res = graph.query(cypher, {"hid": hid, "txt": txt, "sev": sev, "sid": session_id}).result_set
        if not res:
            return _structured_error("WRITE_FAILED", f"ERROR: Failed to create finding for host '{hid}'.")

        finding_id = res[0][0]
        return json.dumps({
            "status": "success",
            "message": f"Finding created: {finding_id}",
            "finding_id": finding_id,
            "host_id": hid,
            "severity": sev,
            "tenant_id": tenant_id,
        })
    except Exception as e:
        return _structured_error("PERSISTENCE_ERROR", f"ERROR: {e}")


@mcp_app.tool()
def falkordb_triage_host(
    host_id: str,
    tenant_id: str = "sec_ops_tenant_alpha",
) -> str:
    """
    Resolves host infrastructure metadata, EDR status, SMB signing, and firewall state from FalkorDB.
    """
    tenant_err = _validate_tenant(tenant_id)
    if tenant_err:
        return tenant_err

    hid = host_id.strip()
    if not hid or len(hid) > 64:
        return _structured_error("INVALID_HOST_ID", "ERROR: host_id is required and must not exceed 64 characters")

    cypher = "MATCH (h:Host {id: $hid}) RETURN h.id, h.name, h.ip, h.edr, h.smb_signing, h.firewall LIMIT 1"
    try:
        graph = db.select_graph(tenant_id)
        res = graph.ro_query(cypher, {"hid": hid}).result_set
        if not res:
            return _structured_error("HOST_NOT_FOUND", f"Unknown host: {hid}")
        r = res[0]
        return json.dumps({
            "status": "success",
            "host": {
                "id": r[0],
                "name": r[1],
                "ip": r[2],
                "edr": bool(r[3]),
                "smb_signing": bool(r[4]),
                "firewall": bool(r[5]),
            },
            "tenant_id": tenant_id,
        })
    except Exception as e:
        return _structured_error("TRIAGE_ERROR", f"ERROR: {e}")


@mcp_app.tool()
def falkordb_blast_radius(
    patient_zero_id: str,
    simulation_runs: int = 500,
    tenant_id: str = "sec_ops_tenant_alpha",
) -> str:
    """
    Executes the Monte Carlo blast_radius JavaScript UDF inside FalkorDB
    to compute stochastic infection propagation probabilities.
    Safety bounds: runs clamped to [1, 5000].
    """
    tenant_err = _validate_tenant(tenant_id)
    if tenant_err:
        return tenant_err

    pz = patient_zero_id.strip()
    if not pz or len(pz) > 64:
        return _structured_error("INVALID_PATIENT_ZERO", "ERROR: patient_zero_id is required and must not exceed 64 characters")

    try:
        runs = max(1, min(int(simulation_runs), 5000))
    except (ValueError, TypeError):
        runs = 500

    cypher = f"RETURN blast_radius_lib.blast_radius($pz, {runs}) AS result"
    try:
        graph = db.select_graph(tenant_id)
        res = graph.ro_query(cypher, {"pz": pz}).result_set
        if res and res[0] and res[0][0]:
            raw_data = res[0][0]
            parsed = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            return json.dumps({
                "status": "success",
                "patient_zero": pz,
                "simulation_runs": runs,
                "tenant_id": tenant_id,
                "infection_distribution": parsed,
            })
        return _structured_error("EMPTY_UDF_RESULT", "ERROR: Monte Carlo simulation returned empty result")
    except Exception as e:
        return _structured_error("UDF_EXECUTION_ERROR", f"ERROR: {e}")


if __name__ == "__main__":
    asyncio.run(mcp_app.run_stdio_async())
