"""
RootMesh — Environment Configuration
"""
from __future__ import annotations

import re
from typing import Set
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEV_SECRETS: Set[str] = {
    "rootmesh-dev-hmac-sha256-secret-key-production-hardening-2026",
    "secret",
    "changeme",
    "admin",
    "password",
    "",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    falkor_host: str = "localhost"
    falkor_port: int = 6379
    falkor_password: str = ""
    tenant_id: str = "sec_ops_tenant_alpha"

    # Authorized tenants list for multi-tenant isolation verification
    authorized_tenants: Set[str] = {"sec_ops_tenant_alpha", "sec_ops_tenant_beta", "enterprise_soc_corp"}

    # App
    app_title: str = "RootMesh — Incident Response & Threat Memory Engine"
    app_version: str = "1.0.0"
    log_level: str = "INFO"

    # Security & JWT Configuration
    jwt_secret: str = "rootmesh-dev-hmac-sha256-secret-key-production-hardening-2026"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "rootmesh-auth"
    jwt_audience: str = "rootmesh-api"
    jwt_expiration_minutes: int = 60
    auth_mode: str = "dev"

    @property
    def is_production(self) -> bool:
        """Returns True if running under production auth enforcement."""
        return self.auth_mode.lower() in {"prod", "production", "enforce"}

    def validate_production_security(self) -> None:
        """
        Enforces that production deployment cannot use default development secrets
        or weak cryptographic keys (<32 characters).
        """
        if self.is_production:
            if self.jwt_secret in INSECURE_DEV_SECRETS or len(self.jwt_secret) < 32:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION FAILURE: Production auth mode cannot use "
                    "default or weak development JWT secrets. A cryptographically random secret "
                    "(at least 32 characters) must be configured via the JWT_SECRET environment variable."
                )

    @classmethod
    def is_valid_tenant(cls, tenant_id: str) -> bool:
        """Validate tenant ID format to prevent injection attacks."""
        if not tenant_id or not isinstance(tenant_id, str):
            return False
        return bool(re.match(r"^[a-zA-Z0-9_-]{3,64}$", tenant_id))


settings = Settings()
