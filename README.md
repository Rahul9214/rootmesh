# RootMesh — Autonomous Threat Memory & Incident Response Engine

> **FalkorDB Graph Hacks 2026 Submission**<br/>
> *Covering Track 1 (Connected Data Actions), Track 2 (Episodic Memory), and Track 3 (Company Brain)*

[![FalkorDB](https://img.shields.io/badge/FalkorDB-6.0-blueviolet)](https://falkordb.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-15-black)](https://nextjs.org)
[![License](https://img.shields.io/badge/license-MIT-violet)](LICENSE)

---

## 🛡️ Executive Summary

RootMesh is a real-time cybersecurity incident response and threat memory engine powered by **FalkorDB GraphBLAS**. When a cyber incident occurs, traditional security tools analyze siloed logs and miss multi-hop threat vectors spanning workstations, jump servers, and restricted databases.

RootMesh models an organization's digital estate as an interconnected **property graph in FalkorDB**:

- **Topology**: Hosts, firewalls, jump servers, and databases
- **Threat Memory**: CVE vulnerabilities, active ransomware worms, breach propagation paths
- **Organizational Context**: System owners, on-call schedules, and engineering teams

By combining variable-length Cypher traversals (`*1..4`), FalkorDB matrix-accelerated PageRank, MaxFlow network egress calculations, and Monte Carlo JavaScript UDFs, RootMesh delivers explainable threat path reasoning with full provenance within a verified sub-50ms GraphBLAS query SLA.

> [!IMPORTANT]
> **Architectural Distinction: Graph-Level Simulated Containment vs. Real Infrastructure Enforcement**<br/>
> RootMesh executes graph-level topological containment and isolation within FalkorDB (`SET h.firewall = true, h.status = 'CONTAINED'`). This immediately updates graph traversals and blast-radius simulations. Physical hardware firewall enforcement (e.g., Palo Alto Networks, iptables, AWS Security Groups) requires an authorized external hardware appliance connector.

---

## 🏆 Hackathon Track Coverage

| Track | Requirement | Implementation |
|-------|------------|----------------|
| **Track 1: Connected Data Actions** | Graph algorithms as agent tools, multi-hop Cypher traversal (`*1..4`), explainable paths | Variable-length traversal (`*1..4`), FalkorDB `algo.pageRank`, `algo.maxFlow`, embedded Monte Carlo JavaScript UDF (`blast_radius`) |
| **Track 2: Agent Memory & Coordination** | Episodic, semantic & procedural memory, multi-tenant graph isolation | `(:Finding)-[:ABOUT]->(:Host)` subgraphs with timestamp and confidence score, isolated FalkorDB graphs per tenant (`sec_ops_tenant_alpha`) |
| **Track 3: Company Brain** | Unified organizational graph linking infrastructure to teams and on-call responders | `(:Team)-[:OWNS]->(:Host)`, `(:Person)-[:ONCALL_FOR]->(:Team)` with shift schedules, sub-50ms SLA on incident responder resolution |

---

## 📐 Graph Schema & Data Model

### Node Labels

| Label | Properties | Purpose |
|-------|------------|---------|
| `:Host` | `id, name, ip, edr, smb_signing, firewall, status` | Network endpoints and servers |
| `:Database` | `id, name, classification, capacity_mbps` | Critical data stores (PII, Credentials) |
| `:CVE` | `id, name, cvss` | Software vulnerabilities |
| `:Team` | `id, name` | Engineering & SecOps teams |
| `:Person` | `id, name, role, email` | Personnel & Incident Responders |
| `:Finding` | `id, text, severity, session_id, at` | Agent episodic memory nodes |

### Relationship Types

| Relationship | Direction | Properties |
|--------------|-----------|------------|
| `:COMMUNICATES` | `(:Host) -> (:Host)` | `bandwidth_mbps` |
| `:EXPOSED_TO` | `(:Host) -> (:Host)` | `bandwidth_mbps` |
| `:HAS_VULNERABILITY` | `(:Host) -> (:CVE)` | — |
| `:STORED_ON` | `(:Database) -> (:Host)` | `bandwidth_mbps` |
| `:OWNS` | `(:Team) -> (:Host)` | `sla_tier` |
| `:ONCALL_FOR` | `(:Person) -> (:Team)` | `schedule, shift_start, shift_end` |
| `:ABOUT` | `(:Finding) -> (:Host)` | `confidence_score` |

---

## ⚡ Core Cypher Queries & Algorithms

### 1. Multi-Hop Attack Path Traversal (`*1..4`)
```cypher
MATCH path = (pZero:Host {id: $patient_zero_id})-[:COMMUNICATES|EXPOSED_TO*1..4]->(target:Host)
RETURN target.name AS target_name, target.ip AS target_ip, length(path) AS hops,
       [n IN nodes(path) | n.name] AS attack_path
ORDER BY hops ASC
```

### 2. PageRank Critical Asset Scoring
```cypher
CALL algo.pageRank('Host', 'COMMUNICATES')
YIELD node, score
RETURN node.name AS host_name, node.ip AS ip, score
ORDER BY score DESC LIMIT 10
```

### 3. MaxFlow Network Data Egress Calculation
```cypher
MATCH (source:Host {id: $source_id}), (sink:Host {id: $sink_id})
CALL algo.maxFlow({
  sourceNodes: [source],
  targetNodes: [sink],
  relationshipTypes: ['COMMUNICATES'],
  capacityProperty: 'bandwidth_mbps'
})
YIELD maxFlow
RETURN maxFlow AS max_egress_mbps
```

### 4. Monte Carlo JavaScript UDF (`blast_radius`)
```javascript
function blast_radius(start_node_id, runs) {
  var infectedCounts = {};
  var it = graph.iterateNodes('Host');
  var startNode = null;
  var step = it.next();
  while (!step.done) {
    if (step.value.attributes && step.value.attributes.id === start_node_id) {
      startNode = step.value;
      break;
    }
    step = it.next();
  }
  if (!startNode) return JSON.stringify({ error: "Host not found" });

  var numRuns = parseInt(runs, 10) || 100;
  for (var r = 0; r < numRuns; r++) {
    var frontier = [startNode];
    var visited = {};
    visited[startNode.id] = true;

    while (frontier.length > 0) {
      var curr = frontier.shift();
      var trav = graph.traverse([curr], { direction: 'outgoing' });
      if (trav && trav.length > 0) {
        var neighbors = trav[0];
        for (var j = 0; j < neighbors.length; j++) {
          var neighbor = neighbors[j];
          if (!neighbor || !neighbor.attributes || visited[neighbor.id]) continue;
          if (!neighbor.labels || neighbor.labels.indexOf('Host') === -1) continue;

          var prob = 0.30;
          if (!neighbor.attributes.firewall) prob += 0.20;
          if (!neighbor.attributes.smb_signing) prob += 0.15;
          if (!neighbor.attributes.edr) prob += 0.25;

          if (Math.random() < prob) {
            visited[neighbor.id] = true;
            frontier.push(neighbor);
            var nm = neighbor.attributes.name || neighbor.attributes.id;
            infectedCounts[nm] = (infectedCounts[nm] || 0) + 1;
          }
        }
      }
    }
  }
  return JSON.stringify(infectedCounts);
}
falkor.register("blast_radius", blast_radius);
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Docker & Docker Compose
- Python 3.12+
- Node.js 20+

### One-Command Launch
```bash
# 1. Clone & enter repo
git clone https://github.com/Rahul9214/rootmesh.git
cd rootmesh

# 2. Start full stack (FalkorDB + Backend + Frontend)
docker compose up --build -d

# 3. Seed threat graph & register Monte Carlo UDF
cd backend
pip install -r requirements.txt
python seed_threat_graph.py

# 4. Run full test suite
pytest -v
```

---

## 🔌 API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/threat/traverse` | Multi-hop variable-length Cypher traversal (`*1..N`) |
| `GET` | `/api/v1/threat/pagerank/{tenant_id}` | FalkorDB `algo.pageRank` critical asset rankings |
| `POST` | `/api/v1/threat/egress` | FalkorDB `algo.maxFlow` data exfiltration calculation |
| `POST` | `/api/v1/threat/shortest-path` | Shortest attack route calculation between hosts |
| `GET` | `/api/v1/threat/topology/{tenant_id}` | Live host inventory with firewall and infection flags |
| `POST` | `/api/v1/threat/contain` | Graph-level simulated host containment in FalkorDB |
| `POST` | `/api/v1/threat/memory/finding` | Persist episodic finding memory node in FalkorDB (Track 2) |
| `GET` | `/api/v1/threat/oncall/{tenant_id}/{host_id}` | Resolve on-call incident responder from graph (Track 3) |
| `WS` | `/ws/threat-stream` | Real-time WebSocket attack propagation event stream |

---

## 🎨 Luxe Obsidian & Vivid Amethyst Design System

| Token | Value | Usage |
|-------|-------|-------|
| Canvas Background | `#0B0D12` | Ultra-dark Obsidian slate |
| Primary Accent | `#8B5CF6` | Vivid Amethyst — hero borders, active nodes |
| Secondary Highlight | `#FFB800` | Electric Amber — threat alerts, CTAs |
| Critical Danger | `#FF453A` | Coral Red — infected host blocks |
| Typography | Inter / JetBrains Mono | UI copy / terminal stream |

---

## 📁 Project Structure

```
rootmesh/
├── docker-compose.yml
├── README.md
├── .gitignore
├── backend/
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── requirements.txt
│   ├── seed_threat_graph.py
│   ├── app/
│   │   ├── main.py              # FastAPI entry + WebSocket
│   │   ├── config.py            # Pydantic Settings
│   │   ├── mcp_server.py        # MCP Tool Server
│   │   ├── agents/
│   │   │   ├── triage.py        # Triage & path traversal agent
│   │   │   ├── mitigation.py    # Egress calculation & containment agent
│   │   │   └── memory.py        # Episodic memory persistence agent
│   │   ├── db/
│   │   │   ├── falkor_client.py # Multi-tenant connection pool
│   │   │   ├── queries.py       # Parameterized Cypher library
│   │   │   └── udfs.js          # Monte Carlo blast_radius UDF
│   │   ├── models/
│   │   │   └── schemas.py       # Pydantic V2 models
│   │   └── routers/
│   │       └── threat_graph.py  # API endpoints
│   └── tests/
│       ├── test_falkordb_engine.py
│       ├── test_agents.py
│       ├── test_cypher.py
│       ├── test_mcp_tools.py
│       ├── test_tenant_isolation.py
│       └── test_websocket.py
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── app/
    │   ├── layout.tsx
    │   └── page.tsx
    └── components/
        ├── HeroSection.tsx
        ├── FallingBlockGrid.tsx
        ├── SwipeableCardStack.tsx
        └── GraphCanvas.tsx
```

---

*RootMesh — Powered by FalkorDB GraphBLAS*
