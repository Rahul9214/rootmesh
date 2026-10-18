"""
RootMesh — FastAPI Entry Point & WebSocket Hub
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers.auth import router as auth_router
from app.routers.incident import router as incident_router
from app.routers.threat_graph import router as threat_router
from app.security.auth import verify_access_token

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("RootMesh-Backend")


# ──────────────────────────────────────────────
# App
# ──────────────────────────────────────────────

app = FastAPI(
    title=settings.app_title,
    version=settings.app_version,
    description="FalkorDB GraphBLAS-backed real-time threat intelligence and memory engine",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(threat_router)
app.include_router(incident_router)


# ──────────────────────────────────────────────
# WebSocket Connection Manager (Tenant Isolated)
# ──────────────────────────────────────────────

from app.websocket import ConnectionManager, ws_manager


@app.websocket("/ws/threat-stream")
async def threat_stream(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    tenant_id: Optional[str] = Query(None),
) -> None:
    """
    Real-time WebSocket endpoint for tenant-isolated attack propagation events.
    Enforces cryptographically signed token validation and rejects unauthorized cross-tenant subscriptions.
    """
    effective_tenant = tenant_id or "sec_ops_tenant_alpha"

    if token:
        try:
            principal = verify_access_token(token)
            if tenant_id and not principal.can_access_tenant(tenant_id):
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION,
                    reason=f"Forbidden: Principal lacks access to tenant '{tenant_id}'.",
                )
                return
            effective_tenant = tenant_id or principal.tenant_id
        except HTTPException as e:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason=f"Authentication failed: {e.detail}",
            )
            return
        except Exception:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Authentication failed: Malformed credentials.",
            )
            return
    else:
        if settings.auth_mode == "dev":
            if not settings.is_valid_tenant(effective_tenant) or effective_tenant not in settings.authorized_tenants:
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION,
                    reason=f"Forbidden: Tenant '{effective_tenant}' not authorized.",
                )
                return
        else:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Authentication required: Token query parameter missing.",
            )
            return

    await ws_manager.connect(websocket, effective_tenant)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                await websocket.send_json({"error": "Malformed JSON payload"})
                continue

            data_type = data.get("type")
            if data_type == "ping":
                await websocket.send_json({
                    "ack": True,
                    "type": "pong",
                    "tenant_id": effective_tenant,
                    "timestamp": int(time.time() * 1000),
                })
            elif data_type == "resync":
                await websocket.send_json({
                    "ack": True,
                    "type": "resync_ack",
                    "tenant_id": effective_tenant,
                    "timestamp": int(time.time() * 1000),
                })
            else:
                await websocket.send_json({
                    "ack": True,
                    "tenant_id": effective_tenant,
                    "received": data,
                })
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ──────────────────────────────────────────────
# Health / Root
# ──────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health() -> dict:
    return {"status": "operational", "engine": "FalkorDB GraphBLAS", "product": "RootMesh"}


@app.get("/", tags=["System"])
async def root() -> dict:
    return {
        "product": "RootMesh",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
    }
