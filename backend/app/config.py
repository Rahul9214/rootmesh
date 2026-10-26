"""
RootMesh — Environment Configuration
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Set
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

    # Environment
    environment: str = "development"
    auth_mode: str = "dev"

    # FalkorDB / Redis connection
    falkor_url: Optional[str] = None
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

    # CORS configuration
    cors_origins: str = "*"

    # Security & Legacy JWT Configuration
    jwt_secret: str = "rootmesh-dev-hmac-sha256-secret-key-production-hardening-2026"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "rootmesh-auth"
    jwt_audience: str = "rootmesh-api"
    jwt_expiration_minutes: int = 60

    # Clerk B2B Authentication Configuration
    clerk_secret_key: Optional[str] = None
    clerk_issuer: Optional[str] = None
    clerk_jwks_url: Optional[str] = None
    clerk_pem_public_key: Optional[str] = None
    clerk_authorized_parties: str = "http://localhost:3000,http://127.0.0.1:3000"
    clerk_org_to_tenant_map: str = '{"org_3Ksr6Xse0JWJkB5GBkJTpvOHCYn": "sec_ops_tenant_alpha", "org_2secops_alpha": "sec_ops_tenant_alpha", "org_2secops_beta": "sec_ops_tenant_beta", "org_enterprise_soc": "enterprise_soc_corp"}'

    # WebSocket Security Configuration
    ws_auth_timeout_seconds: float = 5.0

    @property
    def is_production(self) -> bool:
        """Returns True if running under production auth enforcement or hosted environment."""
        if self.auth_mode.lower() in {"prod", "production", "enforce"}:
            return True
        if self.environment.lower() in {"prod", "production"}:
            return True
        if os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("VERCEL"):
            return True
        return False

    @property
    def allowed_cors_origins(self) -> List[str]:
        """Returns list of parsed authorized CORS origins."""
        if not self.cors_origins or self.cors_origins.strip() == "*":
            return ["*"]
        return [orig.strip() for orig in self.cors_origins.split(",") if orig.strip()]

    @property
    def authorized_parties_list(self) -> List[str]:
        """Returns list of parsed authorized Clerk frontend origins ('azp' claim)."""
        if not self.clerk_authorized_parties or self.clerk_authorized_parties.strip() == "*":
            return ["*"]
        return [orig.strip().rstrip("/") for orig in self.clerk_authorized_parties.split(",") if orig.strip()]

    @property
    def org_to_tenant_mapping(self) -> dict[str, str]:
        """Parses server-side mapping from Clerk Organization IDs to RootMesh tenant contexts."""
        if not self.clerk_org_to_tenant_map:
            return {}
        try:
            import json
            data = json.loads(self.clerk_org_to_tenant_map)
            if isinstance(data, dict):
                return data
            return {}
        except Exception:
            return {}

    def get_tenant_for_org(self, org_id: Optional[str]) -> Optional[str]:
        """
        Resolves trusted RootMesh tenant context from verified Clerk Organization ID.
        Strictly requires an exact, explicitly configured Clerk Organization ID mapping.
        Never trusts organization slug prefixes, wildcard names, or frontend-supplied heuristics.
        """
        if not org_id or not isinstance(org_id, str):
            return None
        mapping = self.org_to_tenant_mapping
        return mapping.get(org_id)

    def validate_production_security(self) -> None:
        """
        Enforces that production deployment cannot use default development secrets
        or missing Clerk verification configuration.
        """
        if self.is_production:
            if self.jwt_secret in INSECURE_DEV_SECRETS or len(self.jwt_secret) < 32:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION FAILURE: Production auth requires a strong "
                    "JWT_SECRET (at least 32 characters) or valid Clerk configuration."
                )
            if self.clerk_jwks_url or self.clerk_pem_public_key:
                if not self.clerk_issuer:
                    raise ValueError(
                        "CRITICAL SECURITY CONFIGURATION FAILURE: Production auth requires trusted "
                        "CLERK_ISSUER configuration."
                    )
                if not self.clerk_org_to_tenant_map or not self.org_to_tenant_mapping:
                    raise ValueError(
                        "CRITICAL SECURITY CONFIGURATION FAILURE: Production auth requires trusted "
                        "CLERK_ORG_TO_TENANT_MAP configuration."
                    )

    @classmethod
    def is_valid_tenant(cls, tenant_id: str) -> bool:
        """Validate tenant ID format to prevent injection attacks."""
        if not tenant_id or not isinstance(tenant_id, str):
            return False
        return bool(re.match(r"^[a-zA-Z0-9_-]{3,64}$", tenant_id))


settings = Settings()
