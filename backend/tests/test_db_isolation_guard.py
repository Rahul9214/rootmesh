"""
RootMesh — Test Database Isolation & Fail-Closed Guard Verification Suite
Verifies:
1. Write-producing operations against persistent port 6379 are blocked fail-closed.
2. Write-producing operations against persistent graphs ('sec_ops_tenant_alpha', 'sec_ops_tenant_beta') are blocked fail-closed.
3. Write-producing operations against non-test graphs (not starting with 'test_') are blocked fail-closed.
4. Test database availability check fails or detects correctly without falling back.
5. Reconfiguring db_pool in test mode with port 6379 raises TestDatabaseIsolationError.
6. GuardedTestGraph transparently permits ro_query on test graphs, but blocks query and delete on protected graphs.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from app.db.falkor_client import FalkorConnectionPool
from app.db.test_guard import (
    PROTECTED_GRAPHS,
    PROTECTED_PORTS,
    TEST_FALKOR_HOST,
    TEST_FALKOR_PORT,
    TEST_TENANT_ALPHA,
    TEST_TENANT_BETA,
    GuardedTestGraph,
    TestDatabaseIsolationError,
    check_test_db_available,
    verify_test_db_isolation,
)


def test_guard_blocks_port_6379_on_writes():
    """Verify write operations against port 6379 raise TestDatabaseIsolationError."""
    with pytest.raises(TestDatabaseIsolationError) as exc_info:
        verify_test_db_isolation(
            host="localhost",
            port=6379,
            graph_name="test_tenant_alpha",
            is_write=True,
        )
    assert "target protected port 6379" in str(exc_info.value)


def test_guard_blocks_persistent_tenant_alpha_writes():
    """Verify write operations against 'sec_ops_tenant_alpha' raise TestDatabaseIsolationError."""
    with pytest.raises(TestDatabaseIsolationError) as exc_info:
        verify_test_db_isolation(
            host="localhost",
            port=6380,
            graph_name="sec_ops_tenant_alpha",
            is_write=True,
        )
    assert "target protected graph 'sec_ops_tenant_alpha'" in str(exc_info.value)


def test_guard_blocks_persistent_tenant_beta_writes():
    """Verify write operations against 'sec_ops_tenant_beta' raise TestDatabaseIsolationError."""
    with pytest.raises(TestDatabaseIsolationError) as exc_info:
        verify_test_db_isolation(
            host="localhost",
            port=6380,
            graph_name="sec_ops_tenant_beta",
            is_write=True,
        )
    assert "target protected graph 'sec_ops_tenant_beta'" in str(exc_info.value)


def test_guard_blocks_non_test_prefixed_graph_writes():
    """Verify write operations against graphs without 'test_' prefix raise TestDatabaseIsolationError."""
    with pytest.raises(TestDatabaseIsolationError) as exc_info:
        verify_test_db_isolation(
            host="localhost",
            port=6380,
            graph_name="production_graph",
            is_write=True,
        )
    assert "must be prefixed with 'test_'" in str(exc_info.value)


def test_guard_permits_isolated_test_graph_writes_on_port_6380():
    """Verify write operations targeting 'test_tenant_alpha' on port 6380 pass guard validation."""
    # Should not raise
    verify_test_db_isolation(
        host="localhost",
        port=6380,
        graph_name=TEST_TENANT_ALPHA,
        is_write=True,
    )
    verify_test_db_isolation(
        host="localhost",
        port=6380,
        graph_name=TEST_TENANT_BETA,
        is_write=True,
    )


def test_guarded_test_graph_blocks_mutation_on_protected_resource():
    """Verify GuardedTestGraph intercepts .query() and .delete() calls on protected resources."""
    mock_raw = MagicMock()
    # Guard configured with protected port 6379
    guarded_6379 = GuardedTestGraph(
        raw_graph=mock_raw,
        tenant_id=TEST_TENANT_ALPHA,
        port=6379,
        host="localhost",
    )
    with pytest.raises(TestDatabaseIsolationError):
        guarded_6379.query("CREATE (n:Test)")
    with pytest.raises(TestDatabaseIsolationError):
        guarded_6379.delete()

    # Guard configured with protected graph
    guarded_alpha = GuardedTestGraph(
        raw_graph=mock_raw,
        tenant_id="sec_ops_tenant_alpha",
        port=6380,
        host="localhost",
    )
    with pytest.raises(TestDatabaseIsolationError):
        guarded_alpha.query("CREATE (n:Test)")
    with pytest.raises(TestDatabaseIsolationError):
        guarded_alpha.delete()

    # ro_query passes through safely
    guarded_alpha.ro_query("MATCH (n) RETURN count(n)")
    mock_raw.ro_query.assert_called_once_with("MATCH (n) RETURN count(n)")


def test_pool_configure_fails_closed_on_port_6379_in_test_mode():
    """Verify FalkorConnectionPool.configure rejects port 6379 when is_test_mode=True."""
    pool = FalkorConnectionPool()
    with pytest.raises(TestDatabaseIsolationError) as exc_info:
        pool.configure(port=6379, is_test_mode=True)
    assert "Cannot configure test mode against persistent production port 6379" in str(exc_info.value)


def test_availability_check_detects_real_endpoint():
    """Verify check_test_db_available detects open and closed ports without falling back."""
    # Test container is running on 6380
    assert check_test_db_available(host="localhost", port=6380) is True
    # Non-existent port must return False, never hang or fall back
    assert check_test_db_available(host="localhost", port=6399, timeout=0.2) is False
