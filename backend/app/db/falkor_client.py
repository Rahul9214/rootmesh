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
        import os
        self._host = settings.falkor_host
        self._port = settings.falkor_port
        self._password = settings.falkor_password
        self._is_test_mode = False

        conn_url = (
            settings.falkor_url
            or os.getenv("FALKOR_URL")
            or os.getenv("REDIS_URL")
            or os.getenv("REDIS_PRIVATE_URL")
        )
        if conn_url:
            self._db = FalkorDB.from_url(conn_url)
            logger.info("FalkorDB connected via private connection URL")
        else:
            kwargs: dict = {
                "host": self._host,
                "port": self._port,
            }
            if self._password:
                kwargs["password"] = self._password
            self._db = FalkorDB(**kwargs)
            logger.info(
                "FalkorDB connected: %s:%d", self._host, self._port
            )
        self._ensure_udf_registered()

    def configure(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        is_test_mode: bool = False,
    ) -> None:
        """
        Reconfigures database pool endpoint.
        Used to bind test execution strictly to isolated, disposable test instances.
        """
        from app.db.test_guard import TestDatabaseIsolationError, verify_test_db_isolation, TEST_FALKOR_PORT

        new_host = host or self._host
        new_port = port if port is not None else self._port
        new_pwd = password if password is not None else self._password

        if is_test_mode and new_port == 6379:
            raise TestDatabaseIsolationError(
                f"FAIL-CLOSED: Cannot configure test mode against persistent production port 6379! "
                f"Use test port {TEST_FALKOR_PORT}."
            )

        self._host = new_host
        self._port = new_port
        self._password = new_pwd
        self._is_test_mode = is_test_mode

        if url:
            self._db = FalkorDB.from_url(url)
        else:
            kwargs: dict = {"host": self._host, "port": self._port}
            if self._password:
                kwargs["password"] = self._password
            self._db = FalkorDB(**kwargs)

        self._ensure_udf_registered()
        logger.info(
            "FalkorDB connection pool reconfigured: %s:%d (test_mode=%s)",
            self._host, self._port, self._is_test_mode
        )

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
        When in test mode, wraps graph in GuardedTestGraph for fail-closed protection.
        """
        tid = tenant_id or settings.tenant_id
        if not settings.is_valid_tenant(tid):
            raise ValueError(f"Invalid or unauthorized tenant identifier: '{tid}'")

        raw_graph = self._db.select_graph(tid)
        if self._is_test_mode:
            from app.db.test_guard import GuardedTestGraph
            return GuardedTestGraph(raw_graph, tid, self._port, self._host)
        return raw_graph

    @property
    def db(self) -> FalkorDB:
        return self._db

    @property
    def is_test_mode(self) -> bool:
        return self._is_test_mode

    @property
    def port(self) -> int:
        return self._port

    @property
    def host(self) -> str:
        return self._host


# Singleton pool — imported everywhere
db_pool = FalkorConnectionPool()
