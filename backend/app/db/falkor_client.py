"""
RootMesh — FalkorDB Multi-Tenant Connection Pool
"""
from __future__ import annotations

import logging
from typing import Optional

from falkordb import FalkorDB, Graph
from app.config import settings

logger = logging.getLogger("RootMesh-DB")


class FalkorConnectionPool:
    """Thread-safe FalkorDB connection pool with multi-tenant graph isolation."""

    def __init__(self) -> None:
        kwargs: dict = {
            "host": settings.falkor_host,
            "port": settings.falkor_port,
        }
        if settings.falkor_password:
            kwargs["password"] = settings.falkor_password
        self._db = FalkorDB(**kwargs)
        logger.info(
            "FalkorDB connected: %s:%d", settings.falkor_host, settings.falkor_port
        )
        self._ensure_udf_registered()

    def _ensure_udf_registered(self) -> None:
        """Register Monte Carlo blast_radius UDF if not already loaded."""
        import pathlib
        udf_path = pathlib.Path(__file__).parent / "udfs.js"
        if udf_path.exists():
            try:
                code = udf_path.read_text(encoding="utf-8")
                self._db.udf_load("blast_radius_lib", code, replace=True)
                logger.info("Monte Carlo UDF 'blast_radius_lib' registered in FalkorDB.")
            except Exception as e:
                logger.warning("FalkorDB UDF registration notice: %s", e)

    def get_tenant_graph(self, tenant_id: Optional[str] = None) -> Graph:
        """
        Return an isolated graph handle for the given tenant.
        Enforces tenant ID format validation to guarantee multi-tenant isolation.
        """
        tid = tenant_id or settings.tenant_id
        if not settings.is_valid_tenant(tid):
            raise ValueError(f"Invalid or unauthorized tenant identifier: '{tid}'")
        return self._db.select_graph(tid)

    @property
    def db(self) -> FalkorDB:
        return self._db


# Singleton pool — imported everywhere
db_pool = FalkorConnectionPool()
