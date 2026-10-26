# RootMesh — System & Security Architecture Specification

**Product Version:** 0.1.0 (Simulation Release Candidate)
**Status:** Controlled Staging Candidate (Graph-Topology Simulation Only)
**Document Classification:** Engineering Architecture Reference

---

## 1. System Architecture Overview

RootMesh is a graph-native, multi-tenant threat intelligence and incident response system designed around **FalkorDB GraphBLAS** matrix acceleration. It combines a real-time reactive Next.js frontend with an asynchronous FastAPI backend and a hardware-accelerated property graph database.

```mermaid
flowchart TD
    subgraph ClientLayer ["Client & Access Layer"]
        PublicBrowser["Public Web Browser / Operator"]
        MobileClient["Mobile Operator (Throttled Radio)"]
    end

    subgraph IdentityLayer ["B2B Identity & Governance Layer"]
        ClerkAuth["Clerk Identity Provider\n(B2B Organizations & RBAC)"]
        JWKS["Clerk JWKS / RS256 Endpoint\n(Public Key Cryptography)"]
    end

    subgraph FrontendApp ["Frontend Application (Next.js 15.5)"]
        NextServer["Next.js Standalone Production Server\n(Port 3000 / 3025)"]
        StaticLanding["Pre-rendered Static Public Landing\n(Immediate FCP/LCP < 2.0s)"]
        Workspaces["Authenticated Threat Workspace\n(GraphCanvas, Deck, Dossier)"]
        EdgeAuth["Middleware Edge Guard\n(Route Protection & Token Passing)"]
    end

    subgraph BackendApp ["Core Backend Services (FastAPI 0.115+)"]
        APIGateway["FastAPI Gateway / Lifespan Manager\n(Port 8000)"]
        CORSMiddleware["Configurable CORS & Origin Guard\n(Fail-Closed Production Check)"]
        JWTVerifier["Cryptographic JWT / Clerk Verifier\n(RS256 Signature & AZP Claim)"]
        TenantResolver["Tenant Resolution Engine\n(Clerk Org ID -> Tenant Mapping)"]
        IncidentService["Incident & Mitigation Service\n(Separation of Duties & Idempotency)"]
        WSManager["WebSocket Connection Manager\n(In-Band Auth & Isolated Broadcast)"]
        MCPServer["Standalone MCP Server\n(Allowlisted Read-Only Agent Tools)"]
    end

    subgraph DataPersistence ["Graph Data & Acceleration Layer"]
        FalkorDB["FalkorDB (Redis Protocol / Port 6379)\n(SuiteSparse GraphBLAS Engine)"]
        TenantAlpha["Graph: sec_ops_tenant_alpha\n(Isolated Tenant Namespace)"]
        TenantBeta["Graph: sec_ops_tenant_beta\n(Isolated Tenant Namespace)"]
        ThreatMemory["Episodic Finding Subgraphs\n(:Finding)-[:ABOUT]->(:Host)"]
        AuditLog["Procedural Execution Audit Receipts\n(:AuditReceipt)-[:EXECUTION_OF]->(:Proposal)"]
    end

    PublicBrowser -->|HTTPS :3000| NextServer
    MobileClient -->|HTTPS :3000| NextServer
    NextServer --> StaticLanding
    PublicBrowser -->|Clerk OAuth / FIDO2| ClerkAuth
    ClerkAuth -.->|JWT Issuance| PublicBrowser
    PublicBrowser -->|Authenticated Session| EdgeAuth
    EdgeAuth --> Workspaces

    Workspaces -->|REST API :8000| APIGateway
    Workspaces -->|WSS /ws/threat-stream| WSManager

    APIGateway --> CORSMiddleware
    CORSMiddleware --> JWTVerifier
    JWTVerifier -.->|JWKS Key Fetch| JWKS
    JWTVerifier --> TenantResolver
    TenantResolver --> IncidentService
    TenantResolver --> WSManager

    IncidentService --> FalkorDB
    WSManager -.->|Live Telemetry| Workspaces
    MCPServer --> FalkorDB

    FalkorDB --- TenantAlpha
    FalkorDB --- TenantBeta
    TenantAlpha --- ThreatMemory
    TenantAlpha --- AuditLog
```

### Core Architecture Components
1. **Frontend App (`frontend/app`)**: Built with Next.js 15.5 (App Router, Turbopack, Tailwind CSS v4). Serves pre-rendered static public landing pages for sub-second FCP, while dynamically mounting authenticated operational workspaces (SVG graph canvas, swipeable action deck, incident timeline).
2. **Backend App (`backend/app`)**: FastAPI asynchronous application running on Python 3.12+ / Uvicorn. Implements strict tenant isolation, role-based separation of duties, and in-band WebSocket telemetry.
3. **Identity Layer**: B2B multi-organization authentication powered by Clerk. Validated server-side via RS256 asynchronous public keys fetched from JWKS. Organization IDs map to dedicated FalkorDB tenant graphs.
4. **FalkorDB Graph Engine**: In-memory property graph engine leveraging SuiteSparse:GraphBLAS linear algebraic operations. Executes multi-hop Cypher traversals, PageRank centrality, and MaxFlow bandwidth bottlenecks in sub-35ms latencies.

---

## 2. Guarded Incident Response Lifecycle

RootMesh strictly implements an 8-stage Human-in-the-Loop lifecycle. Self-approval is architecturally prohibited, and all rejected, expired, or duplicate executions fail closed.

```mermaid
stateDiagram-v2
    direction TB

    [*] --> Stage1_Detection: Sensor Alert Triggered

    state "Stage 1: Patient Zero Ingestion" as Stage1_Detection {
        HostIdentified: Host identified (e.g. host-0)
        AlertIngested: Sensor alert telemetry recorded
    }

    Stage1_Detection --> Stage2_Investigation: Autonomous Sweep Initiated

    state "Stage 2: GraphBLAS Traversal" as Stage2_Investigation {
        MultiHop: Multi-hop lateral search (*1..4)
        PageRank: PageRank structural centrality
        MaxFlow: MaxFlow egress bottleneck
        ShortestPath: Shortest path to restricted DB
    }

    Stage2_Investigation --> Stage3_Persistence: Findings Identified

    state "Stage 3: Episodic Memory Persistence" as Stage3_Persistence {
        SaveFinding: Persist (:Finding)-[:ABOUT]->(:Host)
        AssociateIncident: Link (:Finding)-[:PART_OF_INCIDENT]->(:Incident)
    }

    Stage3_Persistence --> Stage4_Proposal: Formulate Remediation

    state "Stage 4: Containment Proposal" as Stage4_Proposal {
        ProposeAction: Incident Responder creates proposal
        ModeSelected: Mode: GRAPH_TOPOLOGY_SIMULATION
        GenerateKey: Generate unique idempotency_key
        SetTTL: 15-Minute Expiration Timer starts
    }

    Stage4_Proposal --> Stage5_Review: Awaiting Authorized Review

    state "Stage 5: Human-in-the-Loop Review" as Stage5_Review {
        CheckRole: Verify Reviewer Role != Proposer
        Decision: Explicit Decision by Authorized SecOps Lead
    }

    state "Review Decision Branches" as ReviewDecision {
        Decision --> Approved: Decision == APPROVE (Valid Token)
        Decision --> Rejected: Decision == REJECT
        Decision --> Expired: TTL > 15 Minutes
        Decision --> SelfApprovalDenied: Proposer == Reviewer (403 Forbidden)
    }

    Rejected --> FailClosed_Rejected: Topology Unmodified / Audit Recorded
    Expired --> FailClosed_Expired: Proposal Terminated / Status EXPIRED
    SelfApprovalDenied --> FailClosed_Denied: Action Blocked / Security Logged

    FailClosed_Rejected --> [*]
    FailClosed_Expired --> [*]
    FailClosed_Denied --> Stage5_Review

    Approved --> Stage6_Execution: Valid Approval Token Verified

    state "Stage 6: Simulated Containment Execution" as Stage6_Execution {
        SeverEdges: Sever lateral COMMUNICATES & EXPOSED_TO edges
        IsolateHost: SET h.firewall = true, h.status = 'CONTAINED'
        Deduplicate: Check idempotency_key (Prevent replay)
    }

    Stage6_Execution --> Stage7_Verification: Post-Action Graph Scan

    state "Stage 7: Graph Verification" as Stage7_Verification {
        ReTraverse: GraphBLAS scan from Patient Zero
        ConfirmZeroHops: Verify 0 active reachable lateral hops
        ConfirmZeroEgress: Verify perimeter egress reduced to 0.0 Mbps
    }

    Stage7_Verification --> Stage8_AuditReceipt: State Proved Clean

    state "Stage 8: Persisted Procedural Memory" as Stage8_AuditReceipt {
        CreateAudit: Create (:AuditReceipt {verified: true})
        PersistMetrics: Record paths_severed & egress_reduced_mbps
        BroadcastEvent: Emit CONTAINED event via WebSocket
    }

    Stage8_AuditReceipt --> [*]: Lifecycle Complete & Durable
```

### Safety & Governance Guardrails
- **Separation of Duties**: The incident responder proposing containment (`containment:propose`) cannot authorize their own proposal. An explicit reviewer token with `containment:approve` is required.
- **Fail-Closed Default**: Rejections, expired proposals (TTL = 900 seconds), and unauthenticated attempts leave graph topologies completely untouched.
- **Idempotency Enforcement**: Every execution requires an `idempotency_key`. Duplicate submissions return cached audit receipts without re-executing edge severance.
- **Simulation Boundary**: Containment strictly operates in `GRAPH_TOPOLOGY_SIMULATION` mode inside FalkorDB. Hardware switch or firewall enforcement adapters remain external plugins.

---

## 3. FalkorDB Property Graph Data Model

The RootMesh graph schema represents enterprise infrastructure, vulnerability correlations, organizational ownership, runbook playbooks, and threat memory within unified tenant subgraphs.

```mermaid
erDiagram
    Host ||--o{ Host : COMMUNICATES
    Host ||--o{ Host : EXPOSED_TO
    Host ||--o{ CVE : HAS_VULNERABILITY
    Host ||--o{ Service : RUNS_SERVICE
    Database ||--|| Host : STORED_ON
    Team ||--o{ Service : OWNS_SERVICE
    Person ||--o{ Team : ONCALL_FOR
    Service ||--o{ Runbook : HAS_RUNBOOK
    Service ||--o{ Commit : HAS_CHANGE
    Finding ||--|| Host : ABOUT
    Finding ||--|| Incident : PART_OF_INCIDENT
    Incident ||--|| Host : TARGETS
    Incident ||--o{ Host : AFFECTS
    AuditReceipt ||--|| Incident : AUDIT_FOR

    Host {
        string id PK "e.g. host-0, srv-backup"
        string name "Host display label"
        string ip "IPv4 address"
        boolean edr "EDR sensor status"
        boolean smb_signing "SMB packet signing enabled"
        boolean firewall "Host-based firewall enabled"
        string status "ACTIVE or CONTAINED"
    }

    Database {
        string id PK "e.g. db-1"
        string name "e.g. HR-Payroll-DB"
        string classification "PII_RESTRICTED, CONFIDENTIAL"
        float capacity_mbps "Bandwidth throughput ceiling"
    }

    Service {
        string id PK "e.g. srv-internal-api"
        string name "Service display name"
        string tier "Tier-1, Tier-2, Tier-3"
        string repo "Source code repository URL"
    }

    Team {
        string id PK "e.g. team-secops"
        string name "e.g. SecOps Incident Response"
        string slack_channel "#secops-response"
        string escalation_policy "P1-Immediate-Escalation"
    }

    Person {
        string id PK "e.g. user-alex"
        string name "Alex Rivera"
        string email "alex.rivera@rootmesh.internal"
        string role "Senior SecOps Lead"
        string phone "+1-555-0192"
    }

    Runbook {
        string id PK "e.g. rb-iso-001"
        string title "Workstation Lateral Movement Containment SOP"
        string url "https://runbooks.rootmesh.internal/rb-iso-001"
        int sla_minutes "15"
    }

    Commit {
        string sha PK "7f3a9b1c"
        string author "devops-pipeline"
        string message "Disable SMBv1 fallback on transit routers"
        float timestamp "Unix epoch"
    }

    CVE {
        string id PK "CVE-2017-0144"
        string name "EternalBlue SMB Remote Code Execution"
        float cvss "9.8"
    }

    Incident {
        string id PK "inc-18c2b368"
        string title "Autonomous Threat Investigation: host-0"
        string severity "CRITICAL"
        string status "ACTIVE, CONTAINED, or RESOLVED"
        string patient_zero_id "host-0"
        float created_at "Unix epoch"
        float contained_at "Unix epoch"
    }

    Finding {
        string id PK "find-89a1c"
        string text "Unauthenticated SMB lateral propagation detected"
        string severity "CRITICAL"
        string session_id "session-2026-alpha"
        float created_at "Unix epoch"
    }

    AuditReceipt {
        string id PK "audit-77b2e"
        string action_id "act-contain-01"
        string executed_by "Sarah Chen (Authorized Reviewer)"
        float executed_at "Unix epoch"
        string verification "VERIFIED"
        int paths_severed "14"
        float egress_reduced_mbps "43.0"
    }
```

**Illustrative diagram data:** The example identifiers, reviewer name, and numeric audit metrics are synthetic examples, not measured production results or physical network enforcement.


---

## 4. Security & Tenant Boundary Architecture

RootMesh implements multi-tenant isolation at both the application gateway and the database engine layers.

```mermaid
flowchart LR
    subgraph Ingress ["Client Request Context"]
        ReqA["Tenant Alpha Request\nHeader: Bearer <JWT>\nClerk Org: org_2secops_alpha"]
        ReqB["Tenant Beta Request\nHeader: Bearer <JWT>\nClerk Org: org_2secops_beta"]
        ReqBad["Tampered Request\nForged tenant_id: tenant_alpha\nClerk Org: org_2secops_beta"]
    end

    subgraph AuthGateway ["Authentication & Validation Gateway"]
        Verifier["RS256 JWT Signature Verifier\n(Checks Issuer & Expiration)"]
        PartyValidator["Authorized Party (AZP) Check\n(Checks Origin Against Allowlist)"]
        OrgMapper["Clerk Org Mapping Engine\n(Resolves Authorized Tenant Context)"]
        AccessGuard["Tenant Access Guard\n(Matches Requested vs Mapped Tenant)"]
    end

    subgraph DatabaseBoundary ["FalkorDB Database Boundary"]
        PoolManager["FalkorDB Connection Pool\n(Tenant-Validated Graph Selector)"]
        GraphAlpha[("Graph: sec_ops_tenant_alpha\n(Physical Graph Isolation)")]
        GraphBeta[("Graph: sec_ops_tenant_beta\n(Physical Graph Isolation)")]
    end

    ReqA --> Verifier
    ReqB --> Verifier
    ReqBad --> Verifier

    Verifier --> PartyValidator
    PartyValidator --> OrgMapper
    OrgMapper --> AccessGuard

    AccessGuard -->|Valid Alpha Context| PoolManager
    AccessGuard -->|Valid Beta Context| PoolManager
    AccessGuard -->|Mismatch Detected| Denied["403 Forbidden\nCross-Tenant Violation Blocked"]

    PoolManager -->|select_graph('sec_ops_tenant_alpha')| GraphAlpha
    PoolManager -->|select_graph('sec_ops_tenant_beta')| GraphBeta
```

### Security Boundary Guarantees
1. **Physical Namespace Segregation**: Tenant graphs in FalkorDB are completely separate named graphs (`select_graph(tenant_id)`). Cross-tenant queries are syntactically impossible because queries execute strictly within a single graph context.
2. **Server-Side Identity Derivation**: The active tenant context is derived strictly from verified Clerk Organization membership (`org_id`). Frontend-supplied tenant identifiers are cross-checked; mismatches fail immediately with `403 Forbidden`.
3. **In-Band WebSocket Authentication**: WebSocket connections on `/ws/threat-stream` reject query-string tokens (`?token=...`) to prevent credential leakage in proxy and server access logs. Connections must submit a cryptographic authentication frame within 5.0 seconds or face immediate termination.
4. **Test Database Guard (`app/db/test_guard.py`)**: All write-producing tests are hardwired to port 6380 and restricted to graph names prefixed with `test_`. Writes targeting port 6379 or production tenant graphs immediately abort execution with `TestDatabaseIsolationError`.
