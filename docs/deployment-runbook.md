# RootMesh — Controlled Staging Deployment & Operations Runbook

**Product Version:** 0.1.0 (Simulation Release Candidate)
**Target Environments:** Self-Hosted Container Cluster (Docker / Docker Compose), Cloud VM (AWS EC2 / GCP Compute), or Hybrid Orchestration
**Document Classification:** Controlled Staging Operations & Release Engineering

---

## 1. Production Architecture & Service Topology

RootMesh consists of three interconnected service tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Ingress / TLS Termination                      │
│               (Cloudflare / NGINX / Caddy / AWS ALB)                   │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ HTTPS :443                      │ WSS / HTTPS :443
                    ▼                                ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│   Frontend Standalone Server         │  │   FastAPI Core Backend       │
│   (Node.js 20+ / Port 3000)          │  │   (Python 3.12 / Port 8000)  │
│   - Next.js Standalone Runner        │  │   - Uvicorn Asynchronous Hub │
│   - Pre-rendered Static Landing      │  │   - Clerk RS256 Verification │
│   - Static Asset Cache (1 Year)      │  │   - In-band WebSocket Stream │
└──────────────────────────────────────┘  └──────────────┬───────────────┘
                                                         │ TCP :6379
                                                         ▼
                                          ┌──────────────────────────────┐
                                          │   FalkorDB GraphBLAS Engine  │
                                          │   (Port 6379 / Auth Required)│
                                          │   - Named Docker Volume      │
                                          │   - AOF Persistence Enabled  │
                                          │   - Multi-tenant Namespaces  │
                                          └──────────────────────────────┘
```

---

## 2. Environment Configuration & Secret Management

### Production Configuration Requirements
Production environments must enforce fail-closed security. If required authentication or tenant parameters are omitted, the backend intentionally refuses to start.

#### Required Environment Variables

| Variable | Target Service | Purpose | Production Setting / Requirement |
|:---|:---:|:---|:---|
| `ENVIRONMENT` | Backend | Runtime mode | Set to `production` |
| `AUTH_MODE` | Backend | Token verification | Set to `production` or `enforce` |
| `CLERK_SECRET_KEY` | Backend | Clerk Admin API | Secret key (`sk_live_...`) |
| `CLERK_ISSUER` | Backend | JWT issuer validation | Custom domain URL (e.g., `https://auth.rootmesh.io`) |
| `CLERK_JWKS_URL` | Backend | Remote RS256 public keys | `https://auth.rootmesh.io/.well-known/jwks.json` |
| `CLERK_AUTHORIZED_PARTIES` | Backend | Origin validation | Comma-separated allowed frontend origins |
| `CLERK_ORG_TO_TENANT_MAP` | Backend | Org-to-tenant mapping | JSON map (e.g., `{"org_live_alpha":"sec_ops_tenant_alpha"}`) |
| `FALKOR_HOST` | Backend | Database host | Hostname or IP of FalkorDB container / cluster |
| `FALKOR_PORT` | Backend | Database port | Default `6379` |
| `FALKOR_PASSWORD` | Backend | Database auth | High-entropy password (min 32 characters) |
| `CORS_ORIGINS` | Backend | Cross-Origin resource sharing | Specific frontend production domains (never `*`) |
| `NEXT_PUBLIC_API_URL` | Frontend | Backend REST URL | Public HTTPS backend endpoint |
| `NEXT_PUBLIC_WS_URL` | Frontend | Backend WebSocket URL | Public WSS backend endpoint |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Frontend | Clerk client bundle | Publishable key (`pk_live_...`) |

---

## 3. Deployment Procedures

### Option A: Docker Compose Deployment (Recommended for On-Prem / VPC)

1. **Clone the Repository & Review Environment:**
   ```bash
   git clone https://github.com/RootMesh/rootmesh.git
   cd rootmesh
   cp .env.example .env
   # Populate .env with production credentials and high-entropy FALKOR_PASSWORD
   ```

2. **Verify Configuration & Build Context:**
   Ensure `docker-compose.yml` mounts the persistent volume `falkordb_data` and defines healthchecks.

3. **Execute Production Build & Launch:**
   ```bash
   docker compose build --no-cache
   docker compose up -d
   ```

4. **Verify Container States & Health:**
   ```bash
   docker compose ps
   docker compose logs backend
   curl -f http://localhost:8000/health
   ```

---

### Option B: Standalone Next.js & Bare-Metal Process Deployment

1. **Backend Deployment (FastAPI / Uvicorn):**
   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install --upgrade pip
   pip install -r requirements.txt

   export ENVIRONMENT=production
   export AUTH_MODE=production
   export FALKOR_PASSWORD="<STRONG_PASSWORD>"

   uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
   ```

2. **Frontend Deployment (Next.js Standalone):**
   ```bash
   cd frontend
   npm ci
   npm run build
   # npm run build automatically executes "postbuild": "node scripts/copy-standalone-assets.js"

   cd .next/standalone
   export PORT=3000
   export HOSTNAME="0.0.0.0"
   node server.js
   ```

---

## 4. FalkorDB Backup, Snapshot & Recovery Runbook

FalkorDB stores graph topology, attributes, episodic memories, and audit receipts in Redis RDB snapshots and Append-Only Files (AOF).

### 4.1 Live Snapshot Backup (Zero Downtime)

To create an immediate consistent point-in-time snapshot:

```bash
# 1. Trigger background persistence save
docker exec rootmesh-falkordb redis-cli -a "${FALKOR_PASSWORD}" BGSAVE

# 2. Verify snapshot completion
docker exec rootmesh-falkordb redis-cli -a "${FALKOR_PASSWORD}" LASTSAVE

# 3. Copy snapshot to local backup directory (not immutable)
docker cp rootmesh-falkordb:/data/dump.rdb ./backups/dump_$(date +%Y%m%d_%H%M%S).rdb
docker cp rootmesh-falkordb:/data/appendonly.aof ./backups/aof_$(date +%Y%m%d_%H%M%S).aof
```

### 4.2 Disaster Recovery & Restoration

> [!CAUTION]
> Never run `docker compose down -v` in a production environment. The `-v` flag permanently purges Docker volumes, destroying tenant graphs and historical audit receipts.

To restore from a verified snapshot:

1. Stop the application backend services:
   ```bash
   docker compose stop backend frontend
   ```
2. Stop the FalkorDB container:
   ```bash
   docker compose stop falkordb
   ```
3. Replace the data directory contents with the validated backup file:
   ```bash
   cp ./backups/dump_verified.rdb /var/lib/docker/volumes/rootmesh_falkordb_data/_data/dump.rdb
   ```
4. Restart the FalkorDB service and verify graph counts:
   ```bash
   docker compose start falkordb
   # Run read-only verification query
   docker exec rootmesh-falkordb redis-cli -a "${FALKOR_PASSWORD}" GRAPH.QUERY sec_ops_tenant_alpha "MATCH (n) RETURN count(n)"
   ```
5. Resume application services:
   ```bash
   docker compose start backend frontend
   ```

---

## 5. Reverse Proxy & TLS Configuration

For production deployments, terminate TLS using NGINX or Caddy.

### Sample NGINX Ingress Configuration

```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name console.rootmesh.io api.rootmesh.io;
    return 301 https://$host$request_uri;
}

# Frontend Application (Next.js Standalone)
server {
    listen 443 ssl http2;
    server_name console.rootmesh.io;

    ssl_certificate /etc/letsencrypt/live/console.rootmesh.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/console.rootmesh.io/privkey.pem;

    # Immutable static asset caching
    location /_next/static/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        expires 365d;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Backend API & WebSocket Hub
server {
    listen 443 ssl http2;
    server_name api.rootmesh.io;

    ssl_certificate /etc/letsencrypt/live/api.rootmesh.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.rootmesh.io/privkey.pem;

    # REST Endpoints
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket Threat Stream
    location /ws/threat-stream {
        proxy_pass http://127.0.0.1:8000/ws/threat-stream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

---

## 6. Controlled Staging Health Monitoring & Observability

### Health Endpoints
- **Liveness & Database Health:** `GET /health`
  Returns HTTP 200 with JSON payload if the FalkorDB connection pool responds to ping:
  ```json
  {
    "status": "operational",
    "database": "operational",
    "engine": "FalkorDB GraphBLAS",
    "product": "RootMesh",
    "version": "<configured app version>",
    "environment": "<development or production>"
  }
  ```

The response above is illustrative. The `version` field uses `settings.app_version`; `environment` is determined by `settings.is_production`. These values are not hard-coded.

  Returns HTTP 503 Service Unavailable if FalkorDB is unreachable.

### Graceful Termination
The FastAPI application lifespan drains active WebSockets upon SIGTERM/SIGINT:
```python
active_count = len(ws_manager.active_connections)
if active_count > 0:
    logger.info("Server shutting down: gracefully closing active WebSocket connection(s)...")
    await ws_manager.close_all(code=1001, reason="Server shutting down")
```

---

## 7. Release Acceptance Verification Checklist

Execute this checklist on any staging or pre-production environment prior to directing user traffic:

- [ ] **Identity & Authentication:**
  - [ ] Public landing page renders without Clerk loading delay (< 2.0s).
  - [ ] Signing in redirects to authenticated workspace with valid user token.
  - [ ] Organization switcher maps correctly to tenant ID in FalkorDB.
  - [ ] Users in unauthorized organizations receive clear, truthful access-denied views.
- [ ] **Static Asset Delivery:**
  - [ ] `/brand/rootmesh-wordmark.png` returns HTTP 200 (PNG image, ~360 kB).
  - [ ] `/brand/rootmesh-icon.png` returns HTTP 200 (PNG image, ~150 kB).
  - [ ] Brand assets load with zero broken icons on mobile and desktop viewports.
- [ ] **FalkorDB Multi-Tenant Integrity:**
  - [ ] Tenant A cannot view or query assets belonging to Tenant B.
  - [ ] Switching organizations clears operational state and re-fetches isolated graph.
- [ ] **Autonomous Investigation & Cypher Traversal:**
  - [ ] Patient Zero investigation executes in sub-40ms latency.
  - [ ] Multi-hop traversal correctly identifies reachable unfirewalled hosts.
  - [ ] MaxFlow algorithm reports perimeter egress bandwidth.
  - [ ] Shortest path correctly locates proximity to high-value databases.
- [ ] **Incident Response Lifecycle & Separation of Duties:**
  - [ ] Proposing containment creates a proposal in `PENDING` state with an idempotency key.
  - [ ] Self-approval attempts by the proposer fail with 403 Forbidden.
  - [ ] Explicit approval by an authorized reviewer transitions proposal to `APPROVED`.
  - [ ] Rejections fail closed: graph topology remains unchanged.
  - [ ] Simulated containment verification confirms zero modeled active paths and 0.0 Mbps modeled egress for the tested graph scenario.
  - [ ] Graph-backed audit record persistence and cross-session retrieval are verified; tamper-proof immutability is not assumed.
- [ ] **WebSocket Telemetry:**
  - [ ] WebSocket handshake requires in-band authentication within 5.0 seconds.
  - [ ] Query-string tokens are rejected immediately with 1008 Policy Violation.
  - [ ] Containment events broadcast cleanly to connected authorized clients.
