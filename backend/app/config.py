"""
RootMesh — Environment Configuration
"""
from __future__ import annotations

import re
from typing import Set
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @classmethod
    def is_valid_tenant(cls, tenant_id: str) -> bool:
        """Validate tenant ID format to prevent injection attacks."""
        if not tenant_id or not isinstance(tenant_id, str):
            return False
        return bool(re.match(r"^[a-zA-Z0-9_-]{3,64}$", tenant_id))


settings = Settings()
