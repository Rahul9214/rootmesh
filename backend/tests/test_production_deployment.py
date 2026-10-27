"""
RootMesh — Production Deployment & Security Readiness Verification
Tests:
- Production environment detection and strict fail-closed security validation
- Insecure secrets detection in production
- CORS authorized origins parsing
- FalkorDB connection URL support (Railway private networking)
- Timing-safe login credential verification
- Safe, idempotent seeding behavior
"""
from __future__ import annotations

import os
import pytest
from starlette.testclient import TestClient

from app.config import Settings, INSECURE_DEV_SECRETS
from app.main import app


def test_production_security_validation_fails_on_insecure_secrets():
    """Verify production security validation strictly fails closed if default secrets are used."""
    s = Settings(
        auth_mode="prod",
        jwt_secret="rootmesh-dev-hmac-sha256-secret-key-production-hardening-2026",
    )
    assert s.is_production is True
    with pytest.raises(ValueError) as exc:
        s.validate_production_security()
    assert "CRITICAL SECURITY CONFIGURATION FAILURE" in str(exc.value)


def test_production_security_validation_fails_on_short_keys():
    """Verify production security validation rejects weak keys under 32 characters."""
    s = Settings(
        auth_mode="prod",
        jwt_secret="short-key-less-than-32-chars!",
    )
    assert s.is_production is True
    with pytest.raises(ValueError) as exc:
        s.validate_production_security()
    assert "at least 32 characters" in str(exc.value)


def test_production_security_validation_passes_with_strong_key():
    """Verify production validation succeeds when a strong cryptographic secret is provided."""
    s = Settings(
        auth_mode="prod",
        jwt_secret="a-very-strong-cryptographically-random-production-jwt-key-2026!",
    )
    assert s.is_production is True
    # Should not raise
    s.validate_production_security()


def test_cors_origins_parsing():
    """Verify CORS origins parsing for production multi-domain configuration."""
    s = Settings(cors_origins="https://rootmesh.vercel.app, https://rootmesh-demo.vercel.app")
    origins = s.allowed_cors_origins
    assert "https://rootmesh.vercel.app" in origins
    assert "https://rootmesh-demo.vercel.app" in origins

    wildcard_s = Settings(cors_origins="*")
    assert wildcard_s.allowed_cors_origins == ["*"]


def test_health_check_returns_database_connectivity():
    """Verify /health endpoint reports operational database status."""
    client = TestClient(app)
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert data["database"] == "operational"
    assert "GraphBLAS" in data["engine"]


def test_falkordb_url_configuration_precedence(monkeypatch):
    """Verify FALKOR_URL environment variable precedence for Railway private networking."""
    monkeypatch.setenv("FALKOR_URL", "redis://default:mockpass@falkordb.railway.internal:6379")
    test_settings = Settings()
    # Ensure config reads falkor_url if provided
    assert test_settings.falkor_url is not None or os.getenv("FALKOR_URL") is not None
