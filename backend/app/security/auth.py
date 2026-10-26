"""
RootMesh — Production Authentication & Authorization Engine
Enforces cryptographically signed JWT credentials, principal identity validation,
strict workspace membership binding, and Role-Based Access Control (RBAC).
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import jwt
from fastapi import Depends, Header, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.config import settings

logger = logging.getLogger("RootMesh-Security")

# ──────────────────────────────────────────────
# Role-Based Access Control (RBAC) Permissions
# ──────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "investigator": {
        "threat:read",
        "topology:read",
        "pagerank:read",
        "maxflow:read",
        "path:read",
        "oncall:read",
    },
    "analyst": {
        "threat:read",
        "topology:read",
        "pagerank:read",
        "maxflow:read",
        "path:read",
        "oncall:read",
        "memory:read",
        "memory:write",
        "mcp:read",
    },
    "responder": {
        "threat:read",
        "topology:read",
        "pagerank:read",
        "maxflow:read",
        "path:read",
        "oncall:read",
        "memory:read",
        "memory:write",
        "mcp:read",
        "incident:investigate",
        "containment:propose",
    },
    "admin": {
        "threat:read",
        "topology:read",
        "pagerank:read",
        "maxflow:read",
        "path:read",
        "oncall:read",
        "memory:read",
        "memory:write",
        "mcp:read",
        "mcp:write",
        "incident:investigate",
        "containment:propose",
        "containment:approve",
        "containment:execute",
        "tenant:admin",
    },
}

# Pre-seeded directory of authorized workspace principals for local dev and verification
AUTHORIZED_USERS: Dict[str, Dict[str, Any]] = {
    "alex.rivera": {
        "principal_id": "usr-alex-rivera-01",
        "name": "Alex Rivera",
        "email": "alex.rivera@company.com",
        "tenant_id": "sec_ops_tenant_alpha",
        "workspaces": ["sec_ops_tenant_alpha", "sec_ops_tenant_beta"],
        "roles": ["admin"],
    },
    "sarah.chen": {
        "principal_id": "usr-sarah-chen-02",
        "name": "Sarah Chen",
        "email": "sarah.chen@company.com",
        "tenant_id": "sec_ops_tenant_alpha",
        "workspaces": ["sec_ops_tenant_alpha"],
        "roles": ["responder"],
    },
    "marcus.vance": {
        "principal_id": "usr-marcus-vance-03",
        "name": "Marcus Vance",
        "email": "marcus.vance@company.com",
        "tenant_id": "sec_ops_tenant_alpha",
        "workspaces": ["sec_ops_tenant_alpha"],
        "roles": ["analyst"],
    },
    "guest.auditor": {
        "principal_id": "usr-guest-auditor-04",
        "name": "Guest Auditor",
        "email": "auditor@external.org",
        "tenant_id": "sec_ops_tenant_alpha",
        "workspaces": ["sec_ops_tenant_alpha"],
        "roles": ["investigator"],
    },
    "beta.operator": {
        "principal_id": "usr-beta-operator-05",
        "name": "Beta Workspace Lead",
        "email": "operator@beta.tenant",
        "tenant_id": "sec_ops_tenant_beta",
        "workspaces": ["sec_ops_tenant_beta"],
        "roles": ["admin"],
    },
}


class SecurityPrincipal(BaseModel):
    """Authenticated and verified security principal context."""

    principal_id: str
    username: str
    email: str
    tenant_id: str
    roles: List[str]
    permissions: List[str]
    workspaces: List[str]

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def can_access_tenant(self, target_tenant: str) -> bool:
        return target_tenant in self.workspaces


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    principal: SecurityPrincipal


# ──────────────────────────────────────────────
# Cryptographic Token Operations
# ──────────────────────────────────────────────

def create_access_token(
    principal_id: str,
    username: str,
    tenant_id: str,
    roles: List[str],
    workspaces: Optional[List[str]] = None,
    expires_delta: Optional[timedelta] = None,
    custom_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Creates an HMAC-SHA256 signed JWT bound to principal, tenant, and audience."""
    settings.validate_production_security()
    if not settings.is_valid_tenant(tenant_id):
        raise ValueError(f"Invalid tenant ID format: '{tenant_id}'")

    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.jwt_expiration_minutes))

    workspaces = workspaces or [tenant_id]
    permissions: Set[str] = set()
    for role in roles:
        permissions.update(ROLE_PERMISSIONS.get(role, set()))

    payload: Dict[str, Any] = {
        "sub": principal_id,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
        "username": username,
        "tenant_id": tenant_id,
        "workspaces": workspaces,
        "roles": roles,
        "permissions": sorted(list(permissions)),
    }

    if custom_claims:
        payload.update(custom_claims)

    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def verify_access_token(token: str) -> SecurityPrincipal:
    """
    Decodes and cryptographically verifies an access token.
    Enforces signature validity, expiration, issuer, and audience.
    """
    settings.validate_production_security()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Credential token has expired.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"token_expired\""},
        )
    except (jwt.InvalidSignatureError, jwt.InvalidAudienceError, jwt.InvalidIssuerError, jwt.DecodeError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: Invalid token ({type(e).__name__}).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    tenant_id = payload.get("tenant_id")
    if not tenant_id or not settings.is_valid_tenant(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization failed: Token does not contain a valid tenant binding.",
        )

    if tenant_id not in settings.authorized_tenants:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization failed: Tenant '{tenant_id}' is not authorized on this node.",
        )

    return SecurityPrincipal(
        principal_id=payload.get("sub", "unknown"),
        username=payload.get("username", "anonymous"),
        email=payload.get("email", f"{payload.get('username', 'user')}@rootmesh.local"),
        tenant_id=tenant_id,
        roles=payload.get("roles", ["investigator"]),
        permissions=payload.get("permissions", []),
        workspaces=payload.get("workspaces", [tenant_id]),
    )


# ──────────────────────────────────────────────
# FastAPI Dependency Injection Boundary
# ──────────────────────────────────────────────

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_principal(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> SecurityPrincipal:
    """
    Default-to-deny authentication dependency.
    Extracts Bearer token from HTTP Authorization header and verifies claims.
    Under dev mode ('auth_mode == dev'), falls back to a verified dev admin principal
    if no credentials header is provided, preserving local developer velocity and existing tests.
    Under production mode ('auth_mode == prod'), unconditionally rejects unauthenticated requests with 401.
    """
    if not credentials or not credentials.credentials:
        if settings.auth_mode == "dev":
            logger.debug("Unauthenticated request accepted under local development auth mode.")
            return SecurityPrincipal(
                principal_id="usr-dev-admin-00",
                username="alex.rivera",
                email="alex.rivera@company.com",
                tenant_id="sec_ops_tenant_alpha",
                roles=["admin"],
                permissions=sorted(list(ROLE_PERMISSIONS["admin"])),
                workspaces=["sec_ops_tenant_alpha", "sec_ops_tenant_beta"],
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: Missing 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return verify_access_token(credentials.credentials)


def require_permission(required_permission: str):
    """Dependency factory verifying principal possesses the required RBAC permission."""

    def _dependency(principal: SecurityPrincipal = Depends(get_current_principal)) -> SecurityPrincipal:
        if not principal.has_permission(required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Principal lacks required permission '{required_permission}'.",
            )
        return principal

    return _dependency


def enforce_tenant_context(
    requested_tenant_id: str,
    principal: SecurityPrincipal,
) -> None:
    """
    Guarantees request cannot operate across unauthorized tenant boundaries.
    Rejects malformed tenant IDs (400) and unauthorized/cross-tenant access (403).
    """
    if not settings.is_valid_tenant(requested_tenant_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed tenant ID format: '{requested_tenant_id}'",
        )

    if requested_tenant_id not in settings.authorized_tenants:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Tenant '{requested_tenant_id}' is not authorized on this RootMesh node.",
        )

    if not principal.can_access_tenant(requested_tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Cross-tenant access rejected: Principal '{principal.username}' "
                f"is bound to workspaces {principal.workspaces} and cannot access '{requested_tenant_id}'."
            ),
        )


def generate_dev_token(
    username: str = "alex.rivera",
    tenant_id: str = "sec_ops_tenant_alpha",
    roles: Optional[List[str]] = None,
    expires_in_hours: int = 24,
) -> str:
    """Helper to generate local development token with verified signatures."""
    user = AUTHORIZED_USERS.get(username, {
        "principal_id": f"usr-{username}",
        "name": username,
        "email": f"{username}@rootmesh.local",
        "tenant_id": tenant_id,
        "workspaces": [tenant_id],
        "roles": roles or ["admin"],
    })
    return create_access_token(
        principal_id=user["principal_id"],
        username=username,
        tenant_id=tenant_id,
        roles=roles or user.get("roles", ["admin"]),
        workspaces=user.get("workspaces", [tenant_id]),
        expires_delta=timedelta(hours=expires_in_hours),
    )
