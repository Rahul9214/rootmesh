"""
RootMesh — FastAPI Entry Point & WebSocket Hub
"""
from __future__ import annotations

import json
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers.threat_graph import router as threat_router

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

app.include_router(threat_router)


# ──────────────────────────────────────────────
# WebSocket Connection Manager
# ──────────────────────────────────────────────

class ConnectionManager:
    """Manages active WebSocket connections and broadcasts events."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active_connections.append(ws)
        logger.info("WS client connected. Total: %d", len(self.active_connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active_connections:
            self.active_connections.remove(ws)
        logger.info("WS client disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, payload: dict) -> None:
        stale = []
        for ws in self.active_connections:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            if ws in self.active_connections:
                self.active_connections.remove(ws)


ws_manager = ConnectionManager()


@app.websocket("/ws/threat-stream")
async def threat_stream(websocket: WebSocket) -> None:
    """Real-time WebSocket endpoint for live attack propagation events."""
    await ws_manager.connect(websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            # Echo back structured ack; frontend drives events via REST, WS is broadcast only
            await websocket.send_json({"ack": True, "received": json.loads(raw)})
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
