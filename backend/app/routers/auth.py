"""
RootMesh — Authentication & Session Token Router
Exposes token acquisition, dev token issuance, and principal identity inspection.
"""
from __future__ import annotations

import logging
import os
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.security.auth import (
    AUTHORIZED_USERS,
    SecurityPrincipal,
    TokenResponse,
    create_access_token,
    generate_dev_token,
    get_current_principal,
)
from app.config import settings

logger = logging.getLogger("RootMesh-AuthRouter")
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & Access Control"])


class LoginRequest(BaseModel):
    username: str
    secret: str
    tenant_id: Optional[str] = None


class DevTokenRequest(BaseModel):
    username: str = "alex.rivera"
    tenant_id: str = "sec_ops_tenant_alpha"
    roles: List[str] = Field(default_factory=lambda: ["admin"])


@router.post("/token", response_model=TokenResponse)
async def acquire_token(req: LoginRequest):
    """
    Authenticate principal against authorized directory and issue signed JWT.
    Enforces signature, expiration, audience, and tenant binding.
    Strictly disabled in production mode.
    """
    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Legacy password token issuance is disabled in production mode.",
        )

    user = AUTHORIZED_USERS.get(req.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid username or credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Development credentials must be explicitly configured via environment variables
    # (e.g. ROOTMESH_SECRET_ALEX_RIVERA, ROOTMESH_SECRET_SARAH_CHEN).
    # Fails closed if the environment variable is absent or empty.
    env_secret_key = f"ROOTMESH_SECRET_{req.username.upper().replace('.', '_')}"
    expected_secret = os.getenv(env_secret_key)

    if not expected_secret or not expected_secret.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid username or credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not req.secret or not req.secret.strip() or not secrets.compare_digest(expected_secret, req.secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid username or credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tenant_id = req.tenant_id or user["tenant_id"]
    if tenant_id not in user["workspaces"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User '{req.username}' is not a member of requested workspace '{tenant_id}'.",
        )

    token = create_access_token(
        principal_id=user["principal_id"],
        username=req.username,
        tenant_id=tenant_id,
        roles=user["roles"],
        workspaces=user["workspaces"],
    )

    from app.security.auth import verify_access_token
    principal = verify_access_token(token)

    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=settings.jwt_expiration_minutes * 60,
        principal=principal,
    )


@router.post("/dev-token", response_model=TokenResponse)
async def generate_development_token(req: DevTokenRequest):
    """
    Emergency lockdown: HTTP development token issuance is disabled by default.
    Callers must authenticate via /token with configured credentials or an external IdP.
    Internal generate_dev_token() Python helper remains available for backend tests.
    """
    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Development token issuance is strictly disabled in production mode.",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden: Unauthenticated development token issuance over HTTP is disabled.",
    )


@router.get("/me", response_model=SecurityPrincipal)
async def get_authenticated_principal(
    principal: SecurityPrincipal = Depends(get_current_principal),
):
    """Inspect identity, roles, and RBAC permissions of the current authenticated principal."""
    return principal
