"""
RootMesh — WebSocket Connection Manager & Real-Time Event Bus
Provides tenant-isolated broadcast, deduplication, and subscriber management.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger("RootMesh-WebSocket")


class ConnectionManager:
    """Manages tenant-isolated active WebSocket connections and broadcasts events."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []
        self.tenant_connections: Dict[str, Set[WebSocket]] = {}
        self.socket_tenants: Dict[WebSocket, str] = {}
        self.seen_event_ids: Set[str] = set()

    async def connect(self, ws: WebSocket, tenant_id: str = "sec_ops_tenant_alpha") -> None:
        await ws.accept()
        self.active_connections.append(ws)
        if tenant_id not in self.tenant_connections:
            self.tenant_connections[tenant_id] = set()
        self.tenant_connections[tenant_id].add(ws)
        self.socket_tenants[ws] = tenant_id
        logger.info(
            "WS client connected to tenant '%s'. Active for tenant: %d (Total: %d)",
            tenant_id,
            len(self.tenant_connections[tenant_id]),
            len(self.active_connections),
        )

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active_connections:
            self.active_connections.remove(ws)
        tenant_id = self.socket_tenants.pop(ws, None)
        if tenant_id and tenant_id in self.tenant_connections:
            self.tenant_connections[tenant_id].discard(ws)
            if not self.tenant_connections[tenant_id]:
                del self.tenant_connections[tenant_id]
        logger.info("WS client disconnected from tenant '%s'. Total: %d", tenant_id, len(self.active_connections))

    async def broadcast_to_tenant(self, tenant_id: str, payload: dict) -> None:
        """Broadcast payload strictly to WebSockets subscribed to tenant_id with deduplication."""
        event_id = payload.get("event_id") or payload.get("id")
        if event_id:
            if event_id in self.seen_event_ids:
                logger.debug("Duplicate event suppressed for tenant %s: %s", tenant_id, event_id)
                return
            self.seen_event_ids.add(str(event_id))
            if len(self.seen_event_ids) > 10000:
                self.seen_event_ids.clear()

        sockets = list(self.tenant_connections.get(tenant_id, set()))
        stale = []
        for ws in sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)

    async def broadcast(self, payload: dict) -> None:
        """Safe broadcast routing: routes by tenant_id when present, avoiding cross-tenant exposure."""
        tenant_id = payload.get("tenant_id")
        if tenant_id:
            await self.broadcast_to_tenant(tenant_id, payload)
        else:
            stale = []
            for ws in list(self.active_connections):
                try:
                    await ws.send_json(payload)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self.disconnect(ws)


ws_manager = ConnectionManager()
