"""
RootMesh — FastAPI Entry Point & WebSocket Hub
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect, status
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

from contextlib import asynccontextmanager
from app.websocket import ws_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate production security configuration on startup
    if settings.is_production:
        settings.validate_production_security()
        logger.info("[✓] Production security configuration validated successfully.")
    yield
    # Graceful shutdown: close all active WebSocket connections to prevent Uvicorn hang
    active_count = len(ws_manager.active_connections)
    if active_count > 0:
        logger.info("Server shutting down: gracefully closing %d active WebSocket connection(s)...", active_count)
        await ws_manager.close_all(code=1001, reason="Server shutting down")

app = FastAPI(
    title=settings.app_title,
    version=settings.app_version,
    description="FalkorDB GraphBLAS-backed real-time threat intelligence and memory engine",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_cors_origins,
    allow_credentials=True,
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
async def threat_stream(websocket: WebSocket) -> None:
    """
    Real-time WebSocket endpoint for tenant-isolated attack propagation events.
    Security Hardened:
      1. Strictly forbids credentials in query parameters to prevent token leakage in access logs.
      2. Requires cryptographically verified in-band authentication as the first message over the connection.
      3. Enforces an authentication timeout (default 5.0s) and closes unauthenticated connections immediately.
      4. Validates tenant access against the verified principal, strictly preventing cross-tenant leakage.
      5. Supports in-band token renewal over the active connection.
      6. Produces sanitized logs without printing raw JWTs or secrets.
    """
    # Reject credentials in URL query parameters to prevent token leakage in server/proxy access logs
    if "token" in websocket.query_params:
        logger.warning(
            "WebSocket rejected: Token query parameter is forbidden for security. In-band authentication message required."
        )
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Forbidden: Token query parameters are forbidden. Use in-band authentication message.",
        )
        return

    await websocket.accept()

    # Enforce authentication timeout on initial handshake message
    auth_timeout = getattr(settings, "ws_auth_timeout_seconds", 5.0)
    try:
        raw_auth = await asyncio.wait_for(websocket.receive_text(), timeout=auth_timeout)
    except asyncio.TimeoutError:
        logger.warning("WebSocket rejected: Authentication timeout reached (no auth message received within %.1fs).", auth_timeout)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication timeout: Initial authentication message was not received.",
        )
        return
    except WebSocketDisconnect:
        return
    except Exception as e:
        logger.warning("WebSocket handshake read error: %s", type(e).__name__)
        return

    # Parse authentication payload
    try:
        auth_data = json.loads(raw_auth)
    except Exception:
        logger.warning("WebSocket authentication failed: Malformed JSON payload received.")
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication failed: Malformed JSON payload.",
        )
        return

    msg_type = auth_data.get("type") or auth_data.get("action")
    if msg_type not in ("auth", "authenticate"):
        logger.warning("WebSocket authentication failed: Initial message must be of type 'auth', received '%s'.", msg_type)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication failed: First message must be an authentication message.",
        )
        return

    token = auth_data.get("token")
    if not token or not isinstance(token, str) or not token.strip():
        logger.warning("WebSocket authentication failed: Missing token in authentication message.")
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication failed: Missing token in authentication message.",
        )
        return

    # Cryptographically verify the session token
    try:
        principal = verify_access_token(token)
    except HTTPException as e:
        logger.warning("WebSocket authentication failed: %s", e.detail)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason=f"Authentication failed: {e.detail}",
        )
        return
    except Exception as e:
        logger.warning("WebSocket authentication failed: Verification error (%s)", type(e).__name__)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication failed: Invalid credentials.",
        )
        return

    # Validate and map tenant authorization
    requested_tenant = auth_data.get("tenant_id")
    if requested_tenant:
        if not principal.can_access_tenant(requested_tenant):
            logger.warning(
                "WebSocket cross-tenant access rejected: Principal '%s' attempted subscription to tenant '%s'",
                principal.principal_id,
                requested_tenant,
            )
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason=f"Forbidden: Principal lacks access to tenant '{requested_tenant}'.",
            )
            return
        effective_tenant = requested_tenant
    else:
        effective_tenant = principal.tenant_id

    if not effective_tenant:
        logger.warning("WebSocket authentication failed: Principal '%s' has no authorized tenant.", principal.principal_id)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Forbidden: No authorized tenant context.",
        )
        return

    # Register authenticated connection with the tenant connection manager
    await ws_manager.connect(websocket, effective_tenant)
    await websocket.send_json({
        "type": "auth_ok",
        "tenant_id": effective_tenant,
        "principal_id": principal.principal_id,
        "roles": principal.roles,
        "timestamp": int(time.time() * 1000),
    })
    logger.info("WS client authenticated for tenant '%s' (principal: %s)", effective_tenant, principal.principal_id)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                await websocket.send_json({"error": "Malformed JSON payload"})
                continue

            data_type = data.get("type") or data.get("action")
            if data_type in ("token_refresh", "auth", "authenticate"):
                refresh_token = data.get("token")
                if not refresh_token or not isinstance(refresh_token, str):
                    await websocket.send_json({"error": "Missing token in renewal request"})
                    continue
                try:
                    refreshed_principal = verify_access_token(refresh_token)
                    if not refreshed_principal.can_access_tenant(effective_tenant):
                        logger.warning(
                            "WS token renewal rejected: Principal lost access to tenant '%s'",
                            effective_tenant,
                        )
                        await websocket.close(
                            code=status.WS_1008_POLICY_VIOLATION,
                            reason=f"Forbidden: Refreshed token lacks access to tenant '{effective_tenant}'.",
                        )
                        return
                    principal = refreshed_principal
                    await websocket.send_json({
                        "type": "token_refresh_ok",
                        "tenant_id": effective_tenant,
                        "principal_id": principal.principal_id,
                        "timestamp": int(time.time() * 1000),
                    })
                    logger.debug("WS token refreshed for principal '%s'", principal.principal_id)
                except HTTPException as e:
                    logger.warning("WS token refresh rejected: %s", e.detail)
                    await websocket.close(
                        code=status.WS_1008_POLICY_VIOLATION,
                        reason=f"Authentication failed: {e.detail}",
                    )
                    return
                except Exception:
                    await websocket.close(
                        code=status.WS_1008_POLICY_VIOLATION,
                        reason="Authentication failed: Invalid refreshed token.",
                    )
                    return

            elif data_type == "ping":
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
    except asyncio.CancelledError:
        ws_manager.disconnect(websocket)
        raise


# ──────────────────────────────────────────────
# Health / Root
# ──────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health(response: Response) -> dict:
    falkor_status = "operational"
    try:
        from app.db.falkor_client import db_pool
        db_pool.db.connection.ping()
    except Exception as e:
        logger.warning("FalkorDB health check ping failed: %s", e)
        falkor_status = f"unreachable: {e}"

    is_healthy = falkor_status == "operational"
    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "operational" if is_healthy else "degraded",
        "database": falkor_status,
        "engine": "FalkorDB GraphBLAS",
        "product": "RootMesh",
        "version": settings.app_version,
        "environment": "production" if settings.is_production else "development",
    }


@app.get("/", tags=["System"])
async def root() -> dict:
    return {
        "product": "RootMesh",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
    }
