"""
RootMesh — Backend Test Database Isolation & Fail-Closed Guardrails
Enforces strict segregation between live persistent graphs and disposable test resources.
Guarantees write-producing integration tests CANNOT target:
- Port 6379
- Containers 'rootmesh-falkordb' or 'rootmesh-falkordb-legacy'
- Persistent tenant graphs ('sec_ops_tenant_alpha', 'sec_ops_tenant_beta', 'enterprise_soc_corp')
- Any non-test graph (graphs must begin with 'test_')
"""
from __future__ import annotations

import logging
import socket
from typing import Any, Optional, Set

from falkordb import FalkorDB, Graph

logger = logging.getLogger("RootMesh-TestGuard")

PROTECTED_PORTS: Set[int] = {6379}
PROTECTED_HOSTS: Set[str] = {
    "rootmesh-falkordb",
    "rootmesh-falkordb-legacy",
}
PROTECTED_GRAPHS: Set[str] = {
    "sec_ops_tenant_alpha",
    "sec_ops_tenant_beta",
    "enterprise_soc_corp",
}

TEST_FALKOR_HOST = "localhost"
TEST_FALKOR_PORT = 6380
TEST_TENANT_ALPHA = "test_tenant_alpha"
TEST_TENANT_BETA = "test_tenant_beta"


class TestDatabaseIsolationError(RuntimeError):
    """Raised when a test attempts a prohibited write or operation against a protected database resource."""
    __test__ = False


def verify_test_db_isolation(
    host: str,
    port: int,
    graph_name: str,
    is_write: bool = True,
) -> None:
    """
    Enforces fail-closed protection:
    If an operation is write-producing:
    - Port 6379 is strictly blocked.
    - Protected containers are blocked.
    - Persistent tenant graphs are blocked.
    - Non-test graphs (not starting with 'test_') are blocked.
    """
    clean_host = (host or "").strip().lower()
    clean_graph = (graph_name or "").strip()

    if is_write:
        if port in PROTECTED_PORTS:
            raise TestDatabaseIsolationError(
                f"FAIL-CLOSED PROTECTION: Write-producing test attempted to target protected port {port}. "
                f"All integration writes must use isolated test port {TEST_FALKOR_PORT}."
            )

        if clean_host in PROTECTED_HOSTS:
            raise TestDatabaseIsolationError(
                f"FAIL-CLOSED PROTECTION: Write-producing test attempted to target protected container '{host}'."
            )

        if clean_graph in PROTECTED_GRAPHS:
            raise TestDatabaseIsolationError(
                f"FAIL-CLOSED PROTECTION: Write-producing test attempted to target protected graph '{clean_graph}'. "
                f"Tests must use isolated test graphs (e.g., '{TEST_TENANT_ALPHA}')."
            )

        if not clean_graph.startswith("test_"):
            raise TestDatabaseIsolationError(
                f"FAIL-CLOSED PROTECTION: Write-producing test attempted to target non-test graph '{clean_graph}'. "
                f"Test graphs must be prefixed with 'test_'."
            )


def check_test_db_available(host: str = TEST_FALKOR_HOST, port: int = TEST_FALKOR_PORT, timeout: float = 1.0) -> bool:
    """Checks if the isolated test FalkorDB instance is available on the specified loopback port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class GuardedTestGraph:
    """
    Transparent proxy wrapping falkordb.Graph.
    Intercepts write-producing calls (.query, .delete) to enforce fail-closed isolation guards.
    Passes read-only calls (.ro_query) safely.
    """

    def __init__(self, raw_graph: Graph, tenant_id: str, port: int, host: str) -> None:
        self._raw_graph = raw_graph
        self._tenant_id = tenant_id
        self._port = port
        self._host = host

    @property
    def name(self) -> str:
        return self._tenant_id

    def query(self, *args: Any, **kwargs: Any) -> Any:
        verify_test_db_isolation(
            host=self._host,
            port=self._port,
            graph_name=self._tenant_id,
            is_write=True,
        )
        return self._raw_graph.query(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> Any:
        verify_test_db_isolation(
            host=self._host,
            port=self._port,
            graph_name=self._tenant_id,
            is_write=True,
        )
        return self._raw_graph.delete(*args, **kwargs)

    def ro_query(self, *args: Any, **kwargs: Any) -> Any:
        return self._raw_graph.ro_query(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw_graph, name)
