"""
RootMesh — FalkorDB Threat Graph Seeding & Algorithm Execution Engine
Requires: pip install falkordb
Run container: docker run -p 6379:6379 --name rootmesh-falkordb --rm falkordb/falkordb:latest
"""
from __future__ import annotations

import os
import time
import pathlib
from falkordb import FalkorDB

# ──────────────────────────────────────────────
# 1. Connect to FalkorDB (RESP protocol on port 6379)
# ──────────────────────────────────────────────

FALKOR_HOST = os.getenv("FALKOR_HOST", "localhost")
FALKOR_PORT = int(os.getenv("FALKOR_PORT", "6379"))
FALKOR_PASSWORD = os.getenv("FALKOR_PASSWORD", "")
TENANT_ID = os.getenv("TENANT_ID", "sec_ops_tenant_alpha")

conn_kwargs: dict = {"host": FALKOR_HOST, "port": FALKOR_PORT}
if FALKOR_PASSWORD:
    conn_kwargs["password"] = FALKOR_PASSWORD

db = FalkorDB(**conn_kwargs)

# ──────────────────────────────────────────────
# 2. Multi-Tenant Graph Isolation
# ──────────────────────────────────────────────

graph = db.select_graph(TENANT_ID)

try:
    graph.delete()
    print(f"[*] Cleared existing graph: {TENANT_ID}")
except Exception:
    pass

print(f"[*] Initializing RootMesh Threat Model on Graph: {TENANT_ID}...")

# ──────────────────────────────────────────────
# 3. Seed Core Infrastructure & Threat Graph
# ──────────────────────────────────────────────

seed_query = """
// Hosts
CREATE (h0:Host {id: 'host-0', name: 'Workstation-PatientZero', ip: '10.0.1.15',
        edr: false, smb_signing: false, firewall: false})
CREATE (h1:Host {id: 'host-1', name: 'AppServer-Internal',     ip: '10.0.2.10',
        edr: true,  smb_signing: true,  firewall: true})
CREATE (h2:Host {id: 'host-2', name: 'FileBackupServer',       ip: '10.0.2.22',
        edr: true,  smb_signing: false, firewall: true})
CREATE (h3:Host {id: 'host-3', name: 'VLAN-Router',            ip: '10.0.3.1',
        edr: true,  smb_signing: true,  firewall: true})
CREATE (h4:Host {id: 'host-4', name: 'JumpServer-SysAdmin',    ip: '10.0.4.5',
        edr: true,  smb_signing: true,  firewall: true})
CREATE (h5:Host {id: 'host-5', name: 'ReverseProxy',           ip: '10.0.5.1',
        edr: true,  smb_signing: true,  firewall: true})
CREATE (h6:Host {id: 'host-6', name: 'PublicWebServer',        ip: '10.0.5.80',
        edr: true,  smb_signing: true,  firewall: true})
CREATE (h7:Host {id: 'host-7', name: 'EgressFirewall',         ip: '10.0.99.254',
        edr: true,  smb_signing: true,  firewall: true})

// High-Value Data Assets
CREATE (d1:Database {id: 'db-1', name: 'HR-Payroll-DB',      classification: 'PII_RESTRICTED', capacity_mbps: 40})
CREATE (d2:Database {id: 'db-2', name: 'Customer-Vault-DB',  classification: 'CRITICAL',       capacity_mbps: 50})

// CVE Vulnerabilities
CREATE (cve1:CVE {id: 'CVE-2017-0144', name: 'EternalBlue SMBv1 RCE', cvss: 9.8})
CREATE (cve2:CVE {id: 'CVE-2021-44228', name: 'Log4Shell RCE',        cvss: 10.0})

// Vulnerability Links
CREATE (h0)-[:HAS_VULNERABILITY]->(cve1)
CREATE (h1)-[:HAS_VULNERABILITY]->(cve2)

// Network Topology (bandwidth_mbps = MaxFlow weights)
CREATE (h0)-[:COMMUNICATES {bandwidth_mbps: 100}]->(h1)
CREATE (h0)-[:COMMUNICATES {bandwidth_mbps: 50}]->(h2)
CREATE (h1)-[:COMMUNICATES {bandwidth_mbps: 100}]->(h3)
CREATE (h2)-[:COMMUNICATES {bandwidth_mbps: 100}]->(h3)
CREATE (d1)-[:STORED_ON    {bandwidth_mbps: 40}]->(h2)
CREATE (d2)-[:STORED_ON    {bandwidth_mbps: 50}]->(h2)
CREATE (h3)-[:COMMUNICATES {bandwidth_mbps: 80}]->(h4)
CREATE (h3)-[:COMMUNICATES {bandwidth_mbps: 30}]->(h5)
CREATE (h4)-[:COMMUNICATES {bandwidth_mbps: 28}]->(h7)
CREATE (h4)-[:EXPOSED_TO   {bandwidth_mbps: 28}]->(h7)
CREATE (h5)-[:COMMUNICATES {bandwidth_mbps: 15}]->(h6)
CREATE (h6)-[:COMMUNICATES {bandwidth_mbps: 19}]->(h7)
CREATE (h6)-[:EXPOSED_TO   {bandwidth_mbps: 19}]->(h7)

// Organizational Structure (Track 3 - Company Brain)
CREATE (t1:Team {id: 'team-sec', name: 'SecOps Incident Response', slack_channel: '#secops-incidents'})
CREATE (p1:Person {id: 'p-1', name: 'Alex Rivera', role: 'Lead Incident Responder',
        email: 'alex.rivera@company.com', github_user: 'arivera'})
CREATE (p1)-[:MEMBER_OF]->(t1)
CREATE (p1)-[:ONCALL_FOR {schedule: '24x7-Primary', shift_start: '00:00', shift_end: '23:59'}]->(t1)
CREATE (t1)-[:OWNS {sla_tier: 'CRITICAL'}]->(h1)
CREATE (t1)-[:OWNS {sla_tier: 'HIGH'}]->(d1)
"""

graph.query(seed_query)
print("[✓] Threat graph populated successfully.")

# ──────────────────────────────────────────────
# 4. Range & Full-Text Indexes
# ──────────────────────────────────────────────

for idx_query in [
    "CREATE INDEX FOR (h:Host) ON (h.id)",
    "CREATE INDEX FOR (d:Database) ON (d.name)",
    "CREATE INDEX FOR (c:CVE) ON (c.id)",
]:
    try:
        graph.query(idx_query)
    except Exception:
        pass  # Index may already exist

print("[✓] Indexes created.")

# ──────────────────────────────────────────────
# 5. Register Monte Carlo Blast-Radius JavaScript UDF
# ──────────────────────────────────────────────

udf_path = pathlib.Path(__file__).parent / "app" / "db" / "udfs.js"
udf_js_code = udf_path.read_text(encoding="utf-8") if udf_path.exists() else ""

if udf_js_code:
    try:
        db.udf_load("blast_radius_lib", udf_js_code, replace=True)
        print("[✓] JavaScript Monte Carlo UDF 'blast_radius' registered successfully via db.udf_load.")
    except Exception as e:
        print(f"[!] UDF notice: {e}")
else:
    print("[!] UDF file not found — skipping registration.")

# ──────────────────────────────────────────────
# 6. Run Graph Algorithms & Verify
# ──────────────────────────────────────────────

print("\n--- Running Graph Algorithms & Multi-Hop Cypher Queries ---\n")

# PageRank
try:
    pr_results = graph.ro_query("""
        CALL algo.pageRank('Host', 'COMMUNICATES')
        YIELD node, score
        RETURN node.name AS host, score
        ORDER BY score DESC LIMIT 5
    """).result_set
    print("[PageRank Critical Assets]:")
    for row in pr_results:
        print(f"  • {row[0]}: Score = {row[1]:.4f}")
except Exception as e:
    print(f"[!] PageRank: {e}")

# Multi-Hop Traversal
try:
    path_results = graph.ro_query("""
        MATCH path = (pZero:Host {id: 'host-0'})-[:COMMUNICATES|EXPOSED_TO*1..4]->(target:Host)
        RETURN target.name AS compromised_host, length(path) AS distance,
               [n IN nodes(path) | n.name] AS attack_path
        ORDER BY distance ASC
    """).result_set
    print("\n[Multi-Hop Attack Vector Traversal]:")
    for row in path_results:
        print(f"  • Hop {row[1]}: {' -> '.join(row[2])}")
except Exception as e:
    print(f"[!] Traversal: {e}")

print("\n[✓] RootMesh seeding complete. System ready.")
