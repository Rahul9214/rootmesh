"""
RootMesh — Backend Test Configuration & Database Isolation
Ensures test suites execute strictly against the isolated test FalkorDB instance on port 6380.
Guarantees fail-closed isolation from production/persistent port 6379 and persistent graphs.
"""
from __future__ import annotations

import json
import logging
import time
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings
from app.db.falkor_client import db_pool
from app.db.test_guard import (
    PROTECTED_GRAPHS,
    PROTECTED_PORTS,
    TEST_FALKOR_HOST,
    TEST_FALKOR_PORT,
    TEST_TENANT_ALPHA,
    TEST_TENANT_BETA,
    TestDatabaseIsolationError,
    check_test_db_available,
    verify_test_db_isolation,
)

logger = logging.getLogger("RootMesh-TestConfig")

# Global test cryptographic keys for Clerk tests
_test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_test_public_pem = _test_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

# Clean defaults at conftest import time
settings.clerk_jwks_url = None
settings.clerk_pem_public_key = None
settings.clerk_issuer = None
settings.falkor_port = TEST_FALKOR_PORT
settings.tenant_id = TEST_TENANT_ALPHA
settings.authorized_tenants.add(TEST_TENANT_ALPHA)
settings.authorized_tenants.add(TEST_TENANT_BETA)

# Allow test dev users access to isolated test tenants
from app.security.auth import AUTHORIZED_USERS
if TEST_TENANT_ALPHA not in AUTHORIZED_USERS["alex.rivera"]["workspaces"]:
    AUTHORIZED_USERS["alex.rivera"]["workspaces"].extend([TEST_TENANT_ALPHA, TEST_TENANT_BETA])
if TEST_TENANT_ALPHA not in AUTHORIZED_USERS["sarah.chen"]["workspaces"]:
    AUTHORIZED_USERS["sarah.chen"]["workspaces"].append(TEST_TENANT_ALPHA)
if TEST_TENANT_ALPHA not in AUTHORIZED_USERS["marcus.vance"]["workspaces"]:
    AUTHORIZED_USERS["marcus.vance"]["workspaces"].append(TEST_TENANT_ALPHA)
if TEST_TENANT_ALPHA not in AUTHORIZED_USERS["guest.auditor"]["workspaces"]:
    AUTHORIZED_USERS["guest.auditor"]["workspaces"].append(TEST_TENANT_ALPHA)
if "beta.operator" in AUTHORIZED_USERS and TEST_TENANT_BETA not in AUTHORIZED_USERS["beta.operator"]["workspaces"]:
    AUTHORIZED_USERS["beta.operator"]["workspaces"].append(TEST_TENANT_BETA)


def _ensure_test_graph_seeded(graph, tenant_id: str) -> None:
    """Ensures minimal core threat model topology and reference incident exist in test graph."""
    verify_test_db_isolation(
        host=TEST_FALKOR_HOST,
        port=TEST_FALKOR_PORT,
        graph_name=tenant_id,
        is_write=True,
    )
    try:
        res = graph.ro_query("MATCH (h:Host {id: 'host-0'}) RETURN count(h)").result_set
        has_host = res and res[0][0] > 0
    except Exception:
        has_host = False

    if not has_host:
        import os
        import seed_threat_graph  # seeds topology and udfs
        logger.info("Test graph '%s' topology seeded.", tenant_id)

    # Ensure baseline reference incident inc-18c2b368 exists for Action Deck regression tests
    try:
        inc_res = graph.ro_query("MATCH (inc:Incident {id: 'inc-18c2b368'}) RETURN count(inc)").result_set
        if not inc_res or inc_res[0][0] == 0:
            graph.query("""
                MATCH (h0:Host {id: 'host-0'})
                CREATE (inc:Incident {
                    id: 'inc-18c2b368',
                    title: 'Autonomous Threat Investigation: host-0',
                    severity: 'CRITICAL',
                    status: 'CONTAINED',
                    patient_zero_id: 'host-0',
                    created_at: 1792377326.21262,
                    contained_at: 1792387346.4707
                })
                CREATE (inc)-[:TARGETS]->(h0)
                CREATE (inc)-[:AFFECTS]->(h0)
            """)
    except Exception as e:
        logger.warning("Notice ensuring test incident in '%s': %s", tenant_id, e)


@pytest.fixture(scope="session", autouse=True)
def configure_test_database_isolation():
    """
    Session-wide fail-closed protection.
    Configures db_pool strictly to port 6380 with is_test_mode=True.
    Skips or fails if isolated test container on 6380 is unreachable.
    Never silently falls back to port 6379 or persistent graphs.
    """
    # Guard: Must NOT connect to port 6379 in test mode
    if not check_test_db_available(TEST_FALKOR_HOST, TEST_FALKOR_PORT):
        pytest.skip(
            f"Disposable test FalkorDB instance is not available on {TEST_FALKOR_HOST}:{TEST_FALKOR_PORT}. "
            f"Failing closed to prevent interaction with persistent database on port 6379.",
            allow_module_level=True,
        )

    # Reconfigure singleton db_pool strictly to port 6380 with is_test_mode=True
    db_pool.configure(
        host=TEST_FALKOR_HOST,
        port=TEST_FALKOR_PORT,
        is_test_mode=True,
    )
    assert db_pool.port == TEST_FALKOR_PORT
    assert db_pool.is_test_mode is True

    # Ensure test graph alpha has topology
    test_graph = db_pool.get_tenant_graph(TEST_TENANT_ALPHA)
    _ensure_test_graph_seeded(test_graph, TEST_TENANT_ALPHA)


@pytest.fixture(autouse=True)
def isolate_test_settings(monkeypatch, request):
    """
    Ensures per-test settings isolation.
    If the test module is not test_clerk_auth or test_action_deck_regression, Clerk settings remain None.
    Maintains falkor_port = 6380 and test tenant defaults.
    """
    monkeypatch.setattr(settings, "falkor_port", TEST_FALKOR_PORT)
    monkeypatch.setattr(settings, "tenant_id", TEST_TENANT_ALPHA)

    # Ensure authorized tenants set includes test tenants
    auth_tenants = set(settings.authorized_tenants)
    auth_tenants.add(TEST_TENANT_ALPHA)
    auth_tenants.add(TEST_TENANT_BETA)
    monkeypatch.setattr(settings, "authorized_tenants", auth_tenants)

    if "test_clerk_auth" not in request.module.__name__ and "test_action_deck_regression" not in request.module.__name__:
        monkeypatch.setattr(settings, "clerk_jwks_url", None)
        monkeypatch.setattr(settings, "clerk_pem_public_key", None)
        monkeypatch.setattr(settings, "clerk_issuer", None)


@pytest.fixture
def isolated_test_graph():
    """Provides isolated test_tenant_alpha graph handle on port 6380."""
    return db_pool.get_tenant_graph(TEST_TENANT_ALPHA)


@pytest.fixture
def isolated_beta_graph():
    """Provides isolated test_tenant_beta graph handle on port 6380."""
    return db_pool.get_tenant_graph(TEST_TENANT_BETA)
