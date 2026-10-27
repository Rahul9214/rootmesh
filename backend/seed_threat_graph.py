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

conn_url = os.getenv("FALKOR_URL") or os.getenv("REDIS_URL") or os.getenv("REDIS_PRIVATE_URL")
if conn_url:
    db = FalkorDB.from_url(conn_url)
    print(f"[*] Connected to FalkorDB via connection URL")
else:
    conn_kwargs: dict = {"host": FALKOR_HOST, "port": FALKOR_PORT}
    if FALKOR_PASSWORD:
        conn_kwargs["password"] = FALKOR_PASSWORD
    db = FalkorDB(**conn_kwargs)
    print(f"[*] Connected to FalkorDB on {FALKOR_HOST}:{FALKOR_PORT}")

# ──────────────────────────────────────────────
# 2. Multi-Tenant Graph Isolation & Idempotent Seeding
# ──────────────────────────────────────────────

graph = db.select_graph(TENANT_ID)

force_seed = os.getenv("FORCE_SEED", "false").lower() in {"1", "true", "yes"}
already_seeded = False
try:
    check_res = graph.query("MATCH (h:Host) RETURN count(h) AS cnt")
    if check_res.result_set and check_res.result_set[0][0] > 0:
        already_seeded = True
except Exception:
    pass

if already_seeded and not force_seed:
    print(f"[*] Graph '{TENANT_ID}' is already populated. Preserving persistent graph and incident memory. (Set FORCE_SEED=true to force reset)")
else:
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

// Organizational Structure & Company Brain (Track 3)
// Explicitly labeled synthetic demonstration data for hackathon evaluation

CREATE (t1:Team {id: 'team-sec', name: 'SecOps Incident Response', slack_channel: '#secops-incidents', pagerduty_service: 'PD-SECOPS-P1'})
CREATE (t2:Team {id: 'team-infra', name: 'Platform Infrastructure Engineering', slack_channel: '#infra-alerts', pagerduty_service: 'PD-INFRA-TIER0'})
CREATE (t3:Team {id: 'team-edge', name: 'Edge Ingress & Gateway Security', slack_channel: '#edge-team', pagerduty_service: 'PD-EDGE-TIER0'})

CREATE (p1:Person {id: 'p-1', name: 'Alex Rivera', role: 'Lead Incident Responder', email: 'alex.rivera@rootmesh.local', github_user: 'arivera', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (p2:Person {id: 'p-2', name: 'Elena Rostova', role: 'Staff Platform Architect', email: 'elena.rostova@rootmesh.local', github_user: 'erostova', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (p3:Person {id: 'p-3', name: 'Marcus Chen', role: 'Edge Security Engineer', email: 'marcus.chen@rootmesh.local', github_user: 'mchen', data_classification: 'SYNTHETIC_DEMONSTRATION'})

CREATE (p1)-[:MEMBER_OF]->(t1)
CREATE (p2)-[:MEMBER_OF]->(t2)
CREATE (p3)-[:MEMBER_OF]->(t3)

CREATE (p1)-[:ONCALL_FOR {schedule: '24x7-Primary', shift_start: '00:00', shift_end: '23:59'}]->(t1)
CREATE (p2)-[:ONCALL_FOR {schedule: 'Infra-Primary', shift_start: '08:00', shift_end: '20:00'}]->(t2)
CREATE (p3)-[:ONCALL_FOR {schedule: 'Edge-Primary', shift_start: '00:00', shift_end: '12:00'}]->(t3)

// Services Running on Hosts
CREATE (s0:Service {id: 'svc-endpoint-gw', name: 'Corporate Device Gateway', tier: 'Tier-1', repo: 'rootmesh/device-mgmt', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s1:Service {id: 'svc-app-core', name: 'Internal Application Core API', tier: 'Tier-0', repo: 'rootmesh/app-core', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s2:Service {id: 'svc-backup', name: 'Secure Backup & Archive Service', tier: 'Tier-1', repo: 'rootmesh/backup-archiver', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s3:Service {id: 'svc-network-mesh', name: 'VLAN Routing & SDN Core', tier: 'Tier-0', repo: 'rootmesh/sdn-mesh', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s4:Service {id: 'svc-bastion', name: 'Privileged Access Bastion', tier: 'Tier-0', repo: 'rootmesh/bastion-gateway', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s5:Service {id: 'svc-proxy', name: 'Reverse Proxy & TLS Ingress', tier: 'Tier-0', repo: 'rootmesh/edge-proxy', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s6:Service {id: 'svc-web-portal', name: 'Public Web Portal & Customer Gateway', tier: 'Tier-0', repo: 'rootmesh/customer-portal', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (s7:Service {id: 'svc-perimeter-fw', name: 'Perimeter Egress Firewall Service', tier: 'Tier-0', repo: 'rootmesh/perimeter-defense', environment: 'production', data_classification: 'SYNTHETIC_DEMONSTRATION'})

// Host-Service mappings
CREATE (h0)-[:RUNS_SERVICE]->(s0)
CREATE (h1)-[:RUNS_SERVICE]->(s1)
CREATE (h2)-[:RUNS_SERVICE]->(s2)
CREATE (h3)-[:RUNS_SERVICE]->(s3)
CREATE (h4)-[:RUNS_SERVICE]->(s4)
CREATE (h5)-[:RUNS_SERVICE]->(s5)
CREATE (h6)-[:RUNS_SERVICE]->(s6)
CREATE (h7)-[:RUNS_SERVICE]->(s7)

// Service Ownership
CREATE (t1)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s0)
CREATE (t2)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s1)
CREATE (t2)-[:OWNS_SERVICE {sla_tier: 'HIGH'}]->(s2)
CREATE (t2)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s3)
CREATE (t2)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s4)
CREATE (t3)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s5)
CREATE (t3)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s6)
CREATE (t1)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s7)

// Direct Host Ownership (Preserving backward compatibility with Module 001/002 tests)
CREATE (t1)-[:OWNS {sla_tier: 'CRITICAL'}]->(h0)
CREATE (t1)-[:OWNS {sla_tier: 'CRITICAL'}]->(h1)
CREATE (t2)-[:OWNS {sla_tier: 'HIGH'}]->(h2)
CREATE (t2)-[:OWNS {sla_tier: 'CRITICAL'}]->(h3)
CREATE (t2)-[:OWNS {sla_tier: 'CRITICAL'}]->(h4)
CREATE (t3)-[:OWNS {sla_tier: 'CRITICAL'}]->(h5)
CREATE (t3)-[:OWNS_SERVICE {sla_tier: 'CRITICAL'}]->(s5)
CREATE (t3)-[:OWNS {sla_tier: 'CRITICAL'}]->(h6)
CREATE (t1)-[:OWNS {sla_tier: 'CRITICAL'}]->(h7)
CREATE (t1)-[:OWNS {sla_tier: 'HIGH'}]->(d1)
CREATE (t1)-[:OWNS {sla_tier: 'CRITICAL'}]->(d2)

// Runbooks linked to Services & Databases
CREATE (rb0:Runbook {id: 'rb-iso-001', title: 'Workstation Lateral Movement Containment SOP', url: 'https://runbooks.internal/secops/rb-iso-001', steps_count: 5, sla_minutes: 15, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb1:Runbook {id: 'rb-app-042', title: 'Tier-0 Internal App Server Compromise & Memory Forensics', url: 'https://runbooks.internal/infra/rb-app-042', steps_count: 7, sla_minutes: 30, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb2:Runbook {id: 'rb-db-009', title: 'High-Value Database Exfiltration Mitigation & Token Revocation', url: 'https://runbooks.internal/secops/rb-db-009', steps_count: 6, sla_minutes: 10, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb3:Runbook {id: 'rb-bkp-012', title: 'Secure Backup Isolation & Snapshot Quarantine SOP', url: 'https://runbooks.internal/infra/rb-bkp-012', steps_count: 5, sla_minutes: 20, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb4:Runbook {id: 'rb-net-020', title: 'VLAN Router Traffic Shunting & ACL Enforcement SOP', url: 'https://runbooks.internal/infra/rb-net-020', steps_count: 4, sla_minutes: 15, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb5:Runbook {id: 'rb-bas-031', title: 'Privileged Bastion Session Kill & Credential Rotation SOP', url: 'https://runbooks.internal/infra/rb-bas-031', steps_count: 6, sla_minutes: 10, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb6:Runbook {id: 'rb-prx-019', title: 'Reverse Proxy Ingress Shunting & TLS Termination SOP', url: 'https://runbooks.internal/edge/rb-prx-019', steps_count: 5, sla_minutes: 15, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb7:Runbook {id: 'rb-web-005', title: 'Web Gateway Traffic Blackhole & WAF Containment SOP', url: 'https://runbooks.internal/edge/rb-web-005', steps_count: 5, sla_minutes: 15, data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (rb8:Runbook {id: 'rb-fw-099', title: 'Perimeter Egress Port Filtering & Firewall Blackhole SOP', url: 'https://runbooks.internal/secops/rb-fw-099', steps_count: 5, sla_minutes: 10, data_classification: 'SYNTHETIC_DEMONSTRATION'})

CREATE (s0)-[:HAS_RUNBOOK]->(rb0)
CREATE (s1)-[:HAS_RUNBOOK]->(rb1)
CREATE (d1)-[:HAS_RUNBOOK]->(rb2)
CREATE (d2)-[:HAS_RUNBOOK]->(rb2)
CREATE (s2)-[:HAS_RUNBOOK]->(rb3)
CREATE (s3)-[:HAS_RUNBOOK]->(rb4)
CREATE (s4)-[:HAS_RUNBOOK]->(rb5)
CREATE (s5)-[:HAS_RUNBOOK]->(rb6)
CREATE (s6)-[:HAS_RUNBOOK]->(rb7)
CREATE (s7)-[:HAS_RUNBOOK]->(rb8)

// Change Provenance (Git Commits) linked to Services
CREATE (c0:Commit {sha: 'c89e1a4', author: 'arivera', message: 'feat(sec): deploy Zero-Trust SMB endpoint policy', timestamp: '2026-10-18T07:15:00Z', repo: 'rootmesh/device-mgmt', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c1:Commit {sha: 'b44f2d1', author: 'erostova', message: 'fix(core): patch Log4j runtime dependency to 2.17.1', timestamp: '2026-10-17T22:40:00Z', repo: 'rootmesh/app-core', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c2:Commit {sha: 'a77c3e2', author: 'erostova', message: 'chore(backup): enforce immutable WORM storage locks', timestamp: '2026-10-18T05:20:00Z', repo: 'rootmesh/backup-archiver', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c3:Commit {sha: 'd92b115', author: 'erostova', message: 'feat(sdn): push zero-trust ACL to core routers', timestamp: '2026-10-17T19:10:00Z', repo: 'rootmesh/sdn-mesh', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c4:Commit {sha: 'f33e881', author: 'arivera', message: 'fix(bastion): terminate idle SSH jump sessions', timestamp: '2026-10-18T06:00:00Z', repo: 'rootmesh/bastion-gateway', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c5:Commit {sha: 'e11c990', author: 'mchen', message: 'feat(edge): block unauthorized lateral ingress routes', timestamp: '2026-10-18T04:45:00Z', repo: 'rootmesh/edge-proxy', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c6:Commit {sha: 'c55b774', author: 'mchen', message: 'fix(waf): deploy hotfix for ingress perimeter', timestamp: '2026-10-17T21:30:00Z', repo: 'rootmesh/customer-portal', data_classification: 'SYNTHETIC_DEMONSTRATION'})
CREATE (c7:Commit {sha: 'b88a442', author: 'arivera', message: 'feat(firewall): isolate perimeter egress interfaces', timestamp: '2026-10-18T08:00:00Z', repo: 'rootmesh/perimeter-defense', data_classification: 'SYNTHETIC_DEMONSTRATION'})

CREATE (s0)-[:HAS_CHANGE]->(c0)
CREATE (s1)-[:HAS_CHANGE]->(c1)
CREATE (s2)-[:HAS_CHANGE]->(c2)
CREATE (s3)-[:HAS_CHANGE]->(c3)
CREATE (s4)-[:HAS_CHANGE]->(c4)
CREATE (s5)-[:HAS_CHANGE]->(c5)
CREATE (s6)-[:HAS_CHANGE]->(c6)
CREATE (s7)-[:HAS_CHANGE]->(c7)
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
    "CREATE INDEX FOR (s:Service) ON (s.id)",
    "CREATE INDEX FOR (t:Team) ON (t.id)",
    "CREATE INDEX FOR (p:Person) ON (p.id)",
    "CREATE INDEX FOR (r:Runbook) ON (r.id)",
    "CREATE INDEX FOR (inc:Incident) ON (inc.id)",
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
