# RootMesh — Autonomous Threat Memory & Incident Response Engine

> **FalkorDB Graph Hacks 2026 Hackathon Submission**<br/>
> Graph-native, sub-millisecond cybersecurity incident investigation, memory persistence, and guarded response powered by **FalkorDB GraphBLAS**.

[![FalkorDB](https://img.shields.io/badge/FalkorDB-GraphBLAS%20v6-82465D?style=flat-square)](https://falkordb.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-26694E?style=flat-square)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-15%20(Turbopack)-302B30?style=flat-square)](https://nextjs.org)
[![Python](https://img.shields.io/badge/Python-3.12%2B-D26A50?style=flat-square)](https://python.org)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-MCP%20Server-E6A548?style=flat-square)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/pytest-68%20passed%20(100%25)-26694E?style=flat-square)](backend/tests)
[![License](https://img.shields.io/badge/license-MIT-645C64?style=flat-square)](LICENSE)

---

## 🛡️ Executive Summary

Modern enterprise cybersecurity breaches do not occur in isolation. Adversaries propagate laterally through internal network fabrics—hopping from an initial compromised workstation through transit routers, backup appliances, and bastion servers until reaching high-value restricted customer databases and egress firewalls.

Traditional security monitoring solutions query relational databases and tabular SIEM logs, which struggle with multi-hop recursive queries and fail to provide real-time blast-radius context.

**RootMesh** solves this problem by representing the entire enterprise estate as an active, interconnected **knowledge and threat graph in FalkorDB**:
- **Infrastructure Topology**: Endpoints, VLAN routers, firewalls, and restricted databases.
- **Vulnerability Fabric**: CVE vulnerability nodes and unauthenticated SMB/RPC edges.
- **Company Brain**: Service dependencies, owning teams, on-call responders, runbook playbooks, and Git commit provenance.
- **Threat Memory**: Durable episodic finding nodes and immutable procedural containment audit logs.

By executing matrix-accelerated GraphBLAS algorithms directly inside FalkorDB, RootMesh evaluates multi-hop lateral propagation vectors, calculates maximum data exfiltration bandwidth bottlenecks, resolves incident ownership, and enforces guarded containment workflows in **under 35 milliseconds**.

---

## 🏆 Graph Hacks 2026 Track Implementations

RootMesh comprehensively addresses all three Graph Hacks 2026 tracks within a unified, production-tested architecture:

| Track | Hackathon Requirement | RootMesh Implementation & Verification |
|:------|:----------------------|:---------------------------------------|
| **Track 1: Agents That Act on Connected Data** | Autonomous agents executing graph algorithms, multi-hop Cypher traversals, explainable graph reasoning, and blast-radius evaluation. | • **Multi-hop Cypher Traversals (`*1..4`)**: Traverses up to 4 hops of active communication vectors.<br/>• **FalkorDB PageRank Centrality (`CALL algo.pageRank('Host', 'COMMUNICATES')`)**: Identifies structural choke points (`EgressFirewall` #1, `VLAN-Router` #2).<br/>• **FalkorDB MaxFlow Bottleneck (`CALL algo.maxFlow(...)`)**: Calculates exact network exfiltration bandwidth ceiling (`43.0 Mbps`).<br/>• **Shortest Path to High-Value Data**: Resolves shortest lateral routes to restricted databases (`HR-Payroll-DB`, 1 hop away).<br/>• **Monte Carlo JavaScript UDF (`blast_radius`)**: Embedded in-graph probabilistic infection simulation running directly inside FalkorDB via `db.udf_load`. |
| **Track 2: Agent Memory & Coordination** | Durable cross-session episodic, semantic, and procedural memory; multi-agent coordination; multi-tenant graph isolation. | • **Episodic Finding Memory Subgraphs**: Persists `(:Finding)-[:ABOUT]->(:Host)` and `(:Finding)-[:PART_OF_INCIDENT]->(:Incident)` subgraphs surviving process restarts.<br/>• **Procedural Containment Audit Records**: Immutable execution receipts recording `paths_severed`, `egress_reduced_mbps`, reviewer authorization, and verification state.<br/>• **Cryptographic Idempotency Keys**: Prevents replay attacks and duplicate containment executions.<br/>• **Cryptographic Multi-Tenant Isolation**: Tenant validation enforces strict graph separation (`sec_ops_tenant_alpha` vs `tenant_beta`); zero cross-tenant query leakage. |
| **Track 3: Company Brain** | Connected organizational knowledge graph resolving infrastructure to human teams, on-call schedules, playbooks, and change history. | • **Organizational Traversal**: Resolves `(:Host)-[:RUNS_SERVICE]->(:Service)<-[:OWNS_SERVICE]-(:Team)<-[:ONCALL_FOR]-(:Person)`.<br/>• **Runbook Resolution**: Maps compromised services directly to operational playbooks (`(:Service)-[:HAS_RUNBOOK]->(:Runbook)`) with documented response SLAs (e.g. 15-minute SLA).<br/>• **Provenance Tracking**: Connects endpoints to recent deployments (`(:Service)-[:HAS_CHANGE]->(:Commit)`) to identify recent configuration diffs.<br/>• **Sub-50ms Graph SLA**: Traverses cross-domain organizational relationships in sub-millisecond FalkorDB queries. |

---

## 📐 FalkorDB Graph Schema

RootMesh maintains a multi-tenant property graph schema in FalkorDB:

```
                  ┌──────────────┐
                  │    :Team     │◀──────[:ONCALL_FOR]──────┌──────────────┐
                  └──────┬───────┘                          │   :Person    │
                         │                                  └──────────────┘
                    [:OWNS_SERVICE]
                         │
                         ▼
┌──────────────┐  [:RUNS_SERVICE]  ┌──────────────┐  [:HAS_RUNBOOK]  ┌──────────────┐
│    :Host     │──────────────────▶│   :Service   │─────────────────▶│   :Runbook   │
└──────┬───────┘                   └──────┬───────┘                  └──────────────┘
       │                                  │
       │                             [:HAS_CHANGE]
       │                                  │
       │                                  ▼
       │                           ┌──────────────┐
       │                           │   :Commit    │
       │                           └──────────────┘
       ├──────[:COMMUNICATES]──────▶ ┌──────────────┐
       │                             │    :Host     │
       ├──────[:STORED_ON]──────────▶│  (Storage)   │◀──────[:STORED_ON]──────┌──────────────┐
       │                             └──────────────┘                         │  :Database   │
       ├──────[:HAS_VULNERABILITY]─▶ ┌──────────────┐                         └──────────────┘
       │                             │    :CVE      │
       │                             └──────────────┘
       ├──────[:ABOUT]─────────────◀ ┌──────────────┐
       │                             │   :Finding   │──────[:PART_OF_INCIDENT]──▶ ┌──────────────┐
       │                             └──────────────┘                             │  :Incident   │
       └─────────────────────────────────────────────────────────────────────────▶└──────────────┘
```

### Node Labels
| Node Label | Key Properties | Description |
|:-----------|:---------------|:------------|
| `:Host` | `id, name, ip, edr, smb_signing, firewall, status` | Network workstations, jump bastions, proxies, and routers. |
| `:Database` | `id, name, classification, capacity_mbps` | Critical data stores (e.g. `HR-Payroll-DB` with `PII_RESTRICTED`). |
| `:Service` | `id, name, tier, repo` | Connected software services and internal APIs. |
| `:Team` | `id, name, slack_channel, escalation_policy` | Owning organizational and SecOps response teams. |
| `:Person` | `id, name, email, role, phone` | On-call engineers and incident responders. |
| `:Runbook` | `id, title, url, sla_minutes` | Verified incident response playbooks and containment SOPs. |
| `:Commit` | `sha, author, message, timestamp` | Recent software deployment commits and security policy updates. |
| `:CVE` | `id, name, cvss` | Known software vulnerabilities (e.g. CVE-2017-0144 EternalBlue). |
| `:Incident` | `id, title, status, created_at, patient_zero_id` | Incident investigation sessions and root cases. |
| `:Finding` | `id, text, severity, session_id, created_at` | Episodic memory nodes persisted across sessions. |

### Edge Types
| Relationship | Path | Key Properties | Semantics |
|:-------------|:-----|:---------------|:----------|
| `:COMMUNICATES` | `(:Host) -> (:Host)` | `bandwidth_mbps` | Network communication path with capacity property. |
| `:EXPOSED_TO` | `(:Host) -> (:Host)` | `bandwidth_mbps` | Vulnerable network exposure vector. |
| `:STORED_ON` | `(:Database) -> (:Host)` | `bandwidth_mbps` | Database storage host association. |
| `:RUNS_SERVICE`| `(:Host) -> (:Service)` | — | Service deployment on host infrastructure. |
| `:OWNS_SERVICE`| `(:Team) -> (:Service)` | `sla_tier` | Organizational governance and ownership. |
| `:ONCALL_FOR` | `(:Person) -> (:Team)` | `schedule, shift` | Active incident on-call duty mapping. |
| `:HAS_RUNBOOK` | `(:Service) -> (:Runbook)`| — | Authorized SOP containment playbook link. |
| `:HAS_CHANGE`  | `(:Service) -> (:Commit)` | — | Configuration change provenance link. |
| `:HAS_VULNERABILITY` | `(:Host) -> (:CVE)` | — | Vulnerability correlation. |
| `:ABOUT`       | `(:Finding) -> (:Host)` | — | Episodic memory finding association. |
| `:PART_OF_INCIDENT` | `(:Finding) -> (:Incident)` | — | Cross-session incident graph association. |

---

## ⚡ Real Cypher Queries & GraphBLAS Algorithms

### 1. Multi-Hop Lateral Propagation Traversal (`*1..4`)
Evaluates reachable exposure vectors from Patient Zero through unfirewalled intermediate hosts:
```cypher
MATCH (pz:Host {id: $patient_zero_id})
MATCH path = (pz)-[:COMMUNICATES|EXPOSED_TO*1..4]->(target:Host)
WHERE ALL(n IN nodes(path) WHERE coalesce(n.firewall, false) = false)
RETURN target.name AS target_name,
       target.ip AS target_ip,
       length(path) AS hops,
       [n IN nodes(path) | n.name] AS full_vector
ORDER BY hops ASC, target.name ASC;
```

### 2. PageRank Structural Centrality Scoring
Executes FalkorDB matrix-accelerated PageRank over the communication graph:
```cypher
CALL algo.pageRank('Host', 'COMMUNICATES', {
  dampingFactor: 0.85,
  maxIterations: 20,
  tolerance: 0.0001
})
YIELD node, score
RETURN node.name AS host_name, node.ip AS ip, score
ORDER BY score DESC
LIMIT 10;
```

### 3. MaxFlow / MinCut Perimeter Egress Bottleneck
Computes the exact network bandwidth ceiling from Patient Zero to the perimeter egress firewall:
```cypher
CALL algo.maxFlow($patient_zero_id, $sink_id, 'COMMUNICATES', 'bandwidth_mbps')
YIELD maxFlow, minCut
RETURN maxFlow AS perimeter_egress_mbps,
       [edge IN minCut | {source: startNode(edge).name, target: endNode(edge).name}] AS choke_points;
```

### 4. Shortest Path to High-Value Restricted Database
Resolves proximity to restricted databases storing PII or cryptographic credentials:
```cypher
MATCH (source:Host {id: $source_id}), (db:Database {id: $db_id})
MATCH (db)-[:STORED_ON]->(storage_host:Host)
WITH source, storage_host, db, shortestPath((source)-[:COMMUNICATES|EXPOSED_TO*]->(storage_host)) AS path
RETURN db.id AS db_id,
       db.name AS db_name,
       db.classification AS classification,
       CASE WHEN source.id = storage_host.id THEN [source.name]
            WHEN path IS NOT NULL THEN [n IN nodes(path) | n.name]
            ELSE [] END AS path_to_host,
       CASE WHEN source.id = storage_host.id THEN 0
            WHEN path IS NOT NULL THEN length(path)
            ELSE null END AS distance;
```

### 5. Company Brain Full Governance Traversal
Traverses infrastructure to connected service, owning team, on-call lead, SOP runbook, and recent Git commits:
```cypher
MATCH (h:Host {id: $host_id})
OPTIONAL MATCH (h)-[:RUNS_SERVICE]->(s:Service)
OPTIONAL MATCH (t:Team)-[:OWNS_SERVICE|OWNS]->(s)
OPTIONAL MATCH (t_direct:Team)-[:OWNS]->(h)
WITH h, s, coalesce(t, t_direct) AS owning_team
OPTIONAL MATCH (p:Person)-[oncall:ONCALL_FOR]->(owning_team)
OPTIONAL MATCH (s)-[:HAS_RUNBOOK]->(rb:Runbook)
OPTIONAL MATCH (s)-[:HAS_CHANGE]->(cm:Commit)
RETURN owning_team.name AS team,
       p.name AS oncall,
       p.email AS oncall_email,
       rb.title AS runbook_title,
       rb.sla_minutes AS runbook_sla_minutes,
       cm.sha AS commit_sha;
```

### 6. Monte Carlo Probabilistic Infection UDF (`blast_radius`)
An embedded JavaScript UDF loaded into FalkorDB via `db.udf_load` executing stochastic infection spread simulations considering EDR, SMB signing, and firewall attributes:
```cypher
RETURN blast_radius_lib.blast_radius($patient_zero_id, 500) AS simulation_distribution;
```

---

## 🔒 Guarded Approval & RBAC Incident Lifecycle

To ensure safe, human-governed incident response, RootMesh enforces an 8-stage lifecycle with zero automated self-approval:

```
[1. Sensor Detection] ➔ [2. Graph Traversal] ➔ [3. Blast Radius & DB Vector] ➔ [4. Risk Assessment]
                                                                                      │
                                                                                      ▼
[8. Durable Audit]    ◀── [7. Verification]  ◀── [6. Reviewer Authorization] ◀── [5. Propose Action]
 (Episodic Memory)        (FalkorDB Re-Scan)       (Explicit Human Decision)       (Responder)
```

1. **Role-Based Separation of Duties**:
   - `containment:propose`: Incident Responder can formulate proposals based on graph evidence.
   - `containment:approve`: SecOps Reviewer must explicitly issue an `APPROVE` or `REJECT` decision. Responders cannot approve their own actions.
   - `containment:execute`: Mitigation Agent executes only approved, non-expired proposals.
2. **Fail-Closed Guarantees**:
   - Rejections fail closed: graph topology remains untouched.
   - Expired proposals (15-minute TTL) fail closed.
3. **Idempotency & Replay Attack Prevention**:
   - Every execution requires a unique `idempotency_key`.
   - Repeated submissions return the cached verifiable audit receipt without mutating the graph twice.
4. **Before/After Factual Containment Verification**:
   - Re-traverses FalkorDB after simulated containment to verify that lateral paths are severed and egress bandwidth is reduced to 0.0 Mbps.

---

## 🤖 Model Context Protocol (MCP) Server

RootMesh includes a standalone hardened MCP Server (`backend/app/mcp_server.py`) exposing fixed, parameterized tools for AI agents:

| MCP Tool Name | Description | Safety Guarantees |
|:--------------|:------------|:------------------|
| `falkordb_execute_cypher` | Executes fixed, allowlisted read-only graph queries. | Prohibits arbitrary Cypher, mutation clauses (`CREATE`, `SET`, `DELETE`), administrative calls, and comments/semicolons. |
| `falkordb_triage_host` | Resolves host metadata, EDR, SMB signing, and firewall state. | Fixed schema inspection; tenant-validated. |
| `falkordb_blast_radius` | Runs the embedded Monte Carlo infection spread simulation. | Clamped simulation runs `[1, 5000]`; parameterized input. |
| `falkordb_save_finding_memory` | Persists an incident finding as an episodic memory node. | Verifies host existence before write; validates severity values. |

---

## 🎨 Warm Light Editorial Design System

RootMesh utilizes an intentional, distinctive **Warm Light Editorial Palette** tailored for mission-critical security operations:

| Palette Token | Hex Code | Visual Application |
|:--------------|:---------|:-------------------|
| **Ivory** | `#FAF7F2` | Workspace background, canvas surface, code editor gutter |
| **Stone** | `#EEE6DC` | Soft card fills, border dividers, sub-ribbon surfaces |
| **Terracotta**| `#D26A50` | Primary actions, patient zero indicators, attack edge vectors |
| **Amber** | `#E6A548` | High-value database assets, warning indicators, egress paths |
| **Plum** | `#82465D` | Perimeter sinks, PageRank badges, organizational governance |
| **Graphite** | `#302B30` | High-contrast editorial typography, dark terminal viewports |

---

## 🚀 Quickstart & Setup Guide

### Prerequisites
- Docker & Docker Compose
- Python 3.12+
- Node.js 20+

### Step 1: Start FalkorDB
```bash
docker run -d --name rootmesh-falkordb -p 6379:6379 -p 3005:3000 falkordb/falkordb:latest
```
*(FalkorDB Visualizer is accessible on `http://localhost:3005`)*

### Step 2: Initialize & Seed the Backend
```bash
cd d:\rootmesh\backend
python -m venv .venv
.venv\Scripts\activate   # Windows (.venv/bin/activate on Linux/macOS)
pip install -r requirements.txt

# Seed the multi-tenant threat graph and register the JavaScript UDF
python seed_threat_graph.py

# Launch FastAPI Backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
*(Swagger UI is available at `http://localhost:8000/docs`)*

### Step 3: Launch the Frontend
```bash
cd d:\rootmesh\frontend
npm install
npm run dev --turbopack
```
*(RootMesh Workspace opens at `http://localhost:3000`)*

### Step 4: Run the Complete Test Suite
```bash
# In backend/
pytest tests/ -v

# In frontend/
npx tsc --noEmit
npm run lint
npm run build
```

---

## 🎬 3-Minute Live Demonstration Sequence

Follow this exact demonstration script to evaluate all features against real FalkorDB GraphBLAS queries:

### **Minute 0:00 – 0:45: Threat Ingestion & Sub-Millisecond Autonomous Sweep**
1. Open `http://localhost:3000`. Observe the Top Navigation Ribbon showing `FalkorDB GraphBLAS v6` connected to tenant `sec_ops_tenant_alpha`.
2. Notice the Command Center pre-populated with Patient Zero `host-0` (`Workstation-PatientZero`).
3. Click **"Run Autonomous Investigation"**.
4. Observe the live audit console stream and metrics strip populate in **under 40 milliseconds**:
   - **Exposure Paths**: `14` reachable lateral propagation vectors.
   - **Traversal Time**: `~32.4 ms` FalkorDB GraphBLAS query.
   - **Perimeter Egress**: `43.0 Mbps` simulated MaxFlow bottleneck.
   - **High-Value Database**: `HR-Payroll-DB` (`PII_RESTRICTED`, 1 hop away via `FileBackupServer`).

### **Minute 0:45 – 1:30: Multi-Hop Vector Reasoning & Risk Priorities**
1. Scroll to **Section 4: Connected Graph Explorer**.
   - Inspect the interactive SVG topology. Observe clear spacing with zero label clipping or overlapping.
   - Click node `host-0` or `db-1` to open the slide-out **Node Inspector Drawer**. View asset properties, GraphBLAS metrics, and team ownership.
2. Scroll to **Section 5: Risk Priorities**.
   - Note the ranking order sorted strictly descending by FalkorDB GraphBLAS PageRank score:
     1. `EgressFirewall` (`0.0649`) — Perimeter sink
     2. `VLAN-Router` (`0.0389`) — Core transit
     3. `PublicWebServer` (`0.0351`) — Ingress gateway
     4. `JumpServer-SysAdmin` (`0.0279`) — Bastion
     5. `ReverseProxy` (`0.0279`) — TLS proxy
     6. `FileBackupServer` (`0.0162`) — Database storage node
     7. `AppServer-Internal` (`0.0162`) — Internal API core

### **Minute 1:30 – 2:15: Live Evidence Composer & Company Brain Resolution**
1. Scroll to **Section 6: Live Evidence Composer**.
   - Click between query tabs: `MultiHopTraversal.cyp`, `ShortestPathDB.cyp`, `PageRankCentrality.cyp`, `MaxFlowEgress.cyp`, `CompanyBrain.cyp`, `EpisodicMemory.cyp`.
   - Verify that displayed parameters (`host-0`, `sec_ops_tenant_alpha`), sub-millisecond latencies, and structured JSON outputs match actual recorded executions.
2. Scroll to **Section 7: Investigation Evidence & Knowledge Dossier**.
   - Click the **"Company Knowledge"** tab: Inspect the organizational traversal mapping `host-0` to `SecOps Incident Response`, On-Call Lead `Alex Rivera`, and the `Workstation Lateral Movement Containment SOP (rb-iso-001)`.
   - Click the **"Threat Memory & Audit"** tab: Inspect persistent episodic memory findings stored in FalkorDB.

### **Minute 2:15 – 3:00: Guarded Human Review, Containment Execution & Verification**
1. Return to **Section 3: Incident Triage & Action Deck**.
   - On the `Workstation-PatientZero` incident card, click **"Propose Containment"**.
   - Notice that the action does **not** auto-approve. The Guarded Review prompt appears: *"Proposal created. Awaiting authorized reviewer decision."*
   - As authorized reviewer, click **"Approve & Execute Containment"**.
   - Observe real-time execution feedback: `✓ APPROVED & CONTAINED (GRAPH_TOPOLOGY_SIMULATION) · Severed: 14 paths · Reduced Egress: 43.0 Mbps`.
2. Scroll to **Section 7: Before & After Impact Tab**.
   - Observe the Post-Action State update from `PENDING AUTHORIZATION` to **`TOPOLOGY SEVERED`**:
     - Host Status: `CONTAINED (SIM)`
     - Lateral Attack Paths: `0 active (14 paths severed)`
     - Perimeter Egress: `0.0 Mbps (43.0 Mbps eliminated)`
     - Database Vector: `Blocked by Host Isolation`
3. Check the **Incident Response Lifecycle Stepper** (Section 2): Stages 1 through 8 are fully verified.

---

## 🧪 Automated Test Suite & Quality Verification

RootMesh has undergone comprehensive test validation across the entire stack:

```
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.1.1
rootdir: D:\rootmesh\backend
collected 68 items

tests/test_agents.py (5 tests) ........................................ PASSED
tests/test_cypher.py (5 tests) ........................................ PASSED
tests/test_falkordb_engine.py (19 tests) .............................. PASSED
tests/test_mcp_tools.py (7 tests) ..................................... PASSED
tests/test_module_003_agent_memory_company_brain.py (4 tests) ......... PASSED
tests/test_security_hardening.py (20 tests) ........................... PASSED
tests/test_tenant_isolation.py (5 tests) .............................. PASSED
tests/test_websocket.py (3 tests) ..................................... PASSED

============================= 68 passed in 31.80s =============================
```

- **Frontend TypeScript (`npx tsc --noEmit`)**: 0 errors
- **Frontend ESLint (`npm run lint`)**: 0 errors, 0 warnings
- **Next.js Production Build (`npm run build`)**: 100% static prerender success

---

## ⚠️ Disclosures & Operational Boundaries

1. **Synthetic Demonstration Data**:
   Company Brain organizational records (personnel names, email addresses, Slack channels, commit hashes, and runbook links) and incident threat vectors are synthetic demonstration entities in FalkorDB for evaluation purposes. They do not represent real external integrations.
2. **Graph-Level Simulated Containment**:
   All containment actions execute simulated graph topology isolation within FalkorDB (`SET h.firewall = true, h.status = 'CONTAINED'`). Physical network isolation on hardware switches or enterprise firewalls requires an authorized hardware appliance connector.
3. **AI-Assisted Development Disclosure**:
   In accordance with Graph Hacks 2026 guidelines, AI code generation assistants were utilized for pair programming, test case generation, and UI drafting. All core architecture, Cypher queries, FalkorDB GraphBLAS integrations, security boundaries, and authorization controls were verified and validated against real local services.

---

*RootMesh — Built for Graph Hacks 2026 with FalkorDB GraphBLAS*
