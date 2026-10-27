<p align="center">
  <img src="frontend/public/brand/rootmesh-wordmark.png" alt="RootMesh Logo" width="380" />
</p>

<p align="center">
  <strong>Graph-Native Cybersecurity Threat Intelligence, Blast-Radius Reasoning & Guarded Incident Response</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#verified-capabilities">Capabilities</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#testing">Testing</a> •
  <a href="#security-model">Security Model</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#disclosures--operational-boundaries">Operational Boundaries</a>
</p>

---

## Overview

Modern cybersecurity incidents do not unfold across isolated tabular rows. Adversaries traverse enterprise network topology—hopping across unfirewalled VLAN routers, exploiting unauthenticated protocol shares, and probing towards restricted databases and perimeter egress gateways.

**RootMesh** is an enterprise graph threat operations engine powered by **FalkorDB GraphBLAS**. By modeling corporate digital assets, service dependencies, CVE vulnerabilities, and organizational ownership as an active property graph, RootMesh evaluates multi-hop lateral movement vectors, calculates exfiltration bottlenecks, and orchestrates Human-in-the-Loop containment workflows in sub-second latencies.

### Target Personas & Use Cases
- **Security Operations Centers (SOC):** Rapidly assess the true blast radius of Patient Zero hosts and resolve structural choke points.
- **Incident Responders:** Formulate guided mitigation proposals with cryptographic proof of lateral isolation and egress bandwidth reduction.
- **Enterprise SecOps Leads:** Enforce non-repudiable human governance where every containment action requires verified, role-segregated authorization before execution.

---

## Verified Capabilities

RootMesh implements strictly verified, test-backed operational capabilities:

- **Multi-Tenant Property Graph Architecture:** Complete tenant data segregation in FalkorDB namespaces (`sec_ops_tenant_alpha`, `sec_ops_tenant_beta`, `enterprise_soc_corp`).
- **Autonomous Multi-Hop Attack Traversal:** Evaluates up to 4 hops of active communication vectors (`COMMUNICATES`, `EXPOSED_TO`) across unfirewalled hosts in sub-40ms queries.
- **Structural Choke Point Analysis (PageRank):** Hardware-accelerated GraphBLAS PageRank centrality scoring identifying critical transit infrastructure.
- **Perimeter Egress Bottleneck Calculation (MaxFlow):** Computes exact network exfiltration bandwidth ceilings from compromised assets to egress firewalls.
- **High-Value Database Proximity:** Determines shortest lateral routes to restricted databases (e.g., PII payroll data stores).
- **Company Brain Context Resolution:** Traverses service ownership, on-call responders, runbook links, and commit provenance to surface human operational context.
- **Persistent Episodic Threat Memory:** Persists structured findings (`(:Finding)-[:ABOUT]->(:Host)`) durable across server restarts and analyst sessions.
- **Swipeable Incident Triage & Action Deck:** Interactive operational deck supporting keyboard, swipe, and button triage with instant memory persistence and mitigation proposal creation.
- **Guarded Human-in-the-Loop Lifecycle:** Strict 8-stage governance requiring explicit, role-segregated authorization for all containment decisions. Self-approval is architecturally forbidden.
- **Graph Topology Containment Simulation:** Modifies graph topology in real time (`GRAPH_TOPOLOGY_SIMULATION` mode) to sever lateral edges and verify post-action blast-radius elimination.
- **Before-and-After Verification Audits:** Automated graph re-scan proving zero remaining reachable paths and zero egress bandwidth post-containment.
- **Authenticated Real-Time Event Streaming:** Secure, tenant-isolated WebSocket event stream (`/ws/threat-stream`) enforcing in-band authentication.

---

## Architecture

RootMesh is built on a modern, decoupled three-tier architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Next.js 15.5 Frontend                           │
│   (App Router, Tailwind CSS v4, Framer Motion, Standalone Runner)      │
│   - Pre-rendered Static Landing for sub-second FCP                     │
│   - Interactive SVG Graph Canvas & Swipeable Action Deck               │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ HTTPS :8000                     │ WSS /ws/threat-stream
                    ▼                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FastAPI 0.115+ Backend                          │
│   (Python 3.12, Uvicorn, Pydantic v2, PyJWT Cryptography)              │
│   - RS256 Clerk B2B Identity Verification & JWKS Key Rotation          │
│   - Strict Tenant Isolation & Idempotent Proposal Engine               │
│   - Standalone Model Context Protocol (MCP) Server                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Redis Protocol :6379
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       FalkorDB Graph Engine                            │
│   (SuiteSparse GraphBLAS Linear Algebra, Embedded JavaScript UDFs)     │
│   - Matrix-Accelerated Cypher Traversals (*1..4)                       │
│   - In-Graph PageRank, MaxFlow, and Shortest-Path Algorithms           │
│   - Isolated Multi-Tenant Graph Namespaces                             │
└────────────────────────────────────────────────────────────────────────┘
```

For complete architecture specifications, state transition diagrams, and ER data schemas, see [docs/architecture.md](docs/architecture.md).

---

## Quickstart

### Prerequisites
- **Node.js:** v20.x or v22.x (`node -v`)
- **Python:** 3.12.x (`python --version`) with [`uv`](https://github.com/astral-sh/uv) or `pip`
- **Docker & Docker Compose:** Docker Desktop or Docker Engine (`docker --version`)

### 1. Start FalkorDB
Launch the FalkorDB graph engine container:
```bash
docker run -d --name rootmesh-falkordb -p 6379:6379 -p 3005:3000 falkordb/falkordb:latest
```
*(Optional FalkorDB Browser Visualizer will be available on `http://localhost:3005`)*

### 2. Configure Environment Files
Copy the sanitized environment templates:
```bash
# Windows PowerShell
Copy-Item .env.example .env
Copy-Item backend\.env.example backend\.env
Copy-Item frontend\.env.example frontend\.env.local

# Linux / macOS
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env.local
```

### 3. Initialize & Launch the Backend
```bash
cd backend

# Using uv (Recommended)
uv venv
# Activate virtual environment:
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS:        source .venv/bin/activate
uv pip install -r requirements.txt

# Seed the tenant graphs and register the JavaScript UDF:
python seed_threat_graph.py

# Launch FastAPI application:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Backend API documentation (Swagger UI) is available at `http://localhost:8000/docs`.

### 4. Launch the Frontend
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` in your browser.

---

## Testing

RootMesh maintains comprehensive automated regression suites for both frontend and backend.

### Backend Pytest Suite (Port 6380 Test Guard)
To protect persistent graphs, all write-producing backend tests strictly require an isolated test database on port 6380. The test suite automatically fails closed if tests attempt to target port 6379.

1. Launch disposable test database:
   ```bash
   docker run -d --name rootmesh-test-falkordb -p 6380:6379 falkordb/falkordb:latest
   ```
2. Execute test suite:
   ```bash
   cd backend
   pytest -v
   ```
   *Verified: 167 of 167 tests passing (100% pass rate).*

### Frontend Verification Suite
```bash
cd frontend

# Run unit and truthfulness test suite
npm test

# Run strict TypeScript compiler verification
npx tsc --noEmit

# Run ESLint check
npm run lint

# Build standalone production distribution bundle
npm run build
```
*Verified: 67 of 67 tests passing, 0 TypeScript errors, 0 ESLint errors.*

---

## Security Model

1. **Role-Based Separation of Duties:**
   - `containment:propose`: Incident Responders can formulate mitigation proposals based on graph evidence.
   - `containment:approve`: Authorized Reviewers must explicitly review and issue decisions. Proposers cannot approve their own actions.
   - `containment:execute`: Mitigation service executes only valid, approved, unexpired proposals.
2. **Fail-Closed Guarantees:**
   - Unapproved, rejected, or expired proposals (15-minute TTL) terminate with zero graph modifications.
   - In production mode, missing Clerk keys, missing JWT secrets, or insecure default secrets intentionally cause the backend to abort startup.
3. **In-Band WebSocket Authentication:**
   - URL query parameter tokens (`?token=...`) are explicitly rejected to prevent credential leakage in HTTP access and proxy logs.
   - Connections must send an authenticated JSON handshake frame within 5.0 seconds.
4. **Tenant Isolation:**
   - Every tenant graph is a separate physical namespace inside FalkorDB.
   - Tenant IDs are derived exclusively from verified Clerk Organization tokens (`org_id`), not untrusted client headers.

---

## Documentation

Comprehensive engineering documentation is maintained in the `docs/` directory:

- [docs/architecture.md](docs/architecture.md): Complete system architecture, 8-stage incident lifecycle diagrams, FalkorDB property graph entity schemas, and security boundaries.
- [docs/deployment-runbook.md](docs/deployment-runbook.md): Production deployment guide, NGINX TLS reverse proxy configuration, FalkorDB zero-downtime backup & recovery runbook, and staging release acceptance checklist.

---

## Disclosures & Operational Boundaries

1. **Demonstration Topology Data:**
   Organizational Company Brain records (personnel names, contact information, commit hashes, and runbook links) and incident threat vectors are synthetic demonstration entities populated in FalkorDB for evaluation purposes.
2. **Graph Topology Simulation Mode:**
   Containment actions operate in `GRAPH_TOPOLOGY_SIMULATION` mode inside FalkorDB (`SET h.firewall = true, h.status = 'CONTAINED'`). Physical enforcement on enterprise firewalls or switch ports requires an authorized hardware appliance connector.
3. **Mobile Performance Baseline:**
   Mobile audits on simulated 4G mobile devices with 4x CPU slowdown achieve a Lighthouse Performance score of 67 (LCP 4.82s, TBT 514ms). Unthrottled desktop performance achieves a 99 score (LCP 1.0s, TBT 0ms).
4. **Third-Party Development Cookies:**
   Best Practices audits report 77 in development due to third-party Cloudflare cookies (`__cf_bm`, `_cfuvid`) set by Clerk's shared development subdomain (`accounts.dev`). In production deployments with custom domains, this issue is eliminated.
