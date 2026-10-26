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


# ──────────────────────────────────────────────
# Clerk B2B & Cryptographic Token Verification
# ──────────────────────────────────────────────

_jwk_clients: Dict[str, jwt.PyJWKClient] = {}


def _get_jwk_client(jwks_url: str) -> jwt.PyJWKClient:
    """Cached PyJWKClient instance for Clerk JWKS keys."""
    if jwks_url not in _jwk_clients:
        _jwk_clients[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True, max_cached_keys=16)
    return _jwk_clients[jwks_url]


def verify_clerk_token(token: str) -> SecurityPrincipal:
    """
    Decodes and cryptographically verifies a Clerk RS256 session token.
    Validates:
      1. RS256 algorithm and valid headers
      2. Signature using Clerk JWKS endpoint or configured PEM public key
      3. Issuer (if CLERK_ISSUER is configured)
      4. Expiration and Not-Before timestamps
      5. Authorized party ('azp') origin
      6. Clerk Organization membership mapped to trusted RootMesh tenant context
      7. RBAC least privilege mapping with strict separation of duties:
         Clerk org:admin maps to RootMesh responder (cannot approve or execute containment).
         Only explicit rootmesh:admin grants administrative approval/execution powers.
    """
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: Malformed token header ({type(e).__name__}).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    alg = header.get("alg")
    if alg != "RS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: Invalid token algorithm '{alg}'. RS256 is required for Clerk session tokens.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    # Resolve cryptographic key strictly from configured public key or trusted JWKS endpoint.
    # NEVER discover or fetch keys from an untrusted URL or issuer supplied by an unverified token.
    key = None
    if settings.clerk_pem_public_key:
        key = settings.clerk_pem_public_key.strip()
    elif settings.clerk_jwks_url:
        try:
            client = _get_jwk_client(settings.clerk_jwks_url)
            signing_key = client.get_signing_key_from_jwt(token)
            key = signing_key.key
        except Exception as e:
            logger.error("Failed to retrieve signing key from Clerk JWKS: %s", type(e).__name__)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: Could not resolve key from Clerk JWKS ({type(e).__name__}).",
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR if settings.is_production else status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Clerk verification configuration (CLERK_JWKS_URL or CLERK_PEM_PUBLIC_KEY) is missing.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    # Require explicitly configured trusted Clerk issuer
    if not settings.clerk_issuer:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR if settings.is_production else status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Trusted Clerk issuer is not configured on server (missing CLERK_ISSUER).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    decode_kwargs: Dict[str, Any] = {
        "algorithms": ["RS256"],
        "issuer": settings.clerk_issuer,
        "options": {
            "require": ["exp", "sub", "iss"],
            "verify_exp": True,
            "verify_iss": True,
        },
    }

    try:
        payload = jwt.decode(token, key, **decode_kwargs)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Clerk session token has expired.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"token_expired\""},
        )
    except jwt.ImmatureSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Clerk session token is not yet valid (nbf).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid token issuer.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid cryptographic signature.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: Invalid Clerk token ({type(e).__name__}).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    # Validate nbf with leeway
    nbf = payload.get("nbf")
    if nbf and nbf > (time.time() + 5):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Clerk session token is not yet valid (nbf check).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    # Validate authorized frontend origin ('azp' claim)
    azp = payload.get("azp")
    if azp and settings.authorized_parties_list != ["*"]:
        clean_azp = azp.rstrip("/")
        if clean_azp not in settings.authorized_parties_list:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: Authorized party '{azp}' is not authorized for RootMesh API.",
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
            )

    # Validate Clerk Organization Context and map strictly to Tenant Context
    # Must use verified Organization ID claim. Never use organization slug prefixes or wildcard mappings.
    org_obj = payload.get("o") if isinstance(payload.get("o"), dict) else {}
    org_id = payload.get("org_id") or org_obj.get("id")

    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization failed: Clerk session token lacks organization context ('org_id' or 'o.id'). A valid organization membership is required.",
        )

    tenant_id = settings.get_tenant_for_org(org_id)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization failed: Organization '{org_id}' is not mapped to an authorized RootMesh tenant context.",
        )

    if tenant_id not in settings.authorized_tenants:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization failed: Tenant '{tenant_id}' is not authorized on this RootMesh node.",
        )

    # Map RBAC Role with strict separation of duties
    org_role = str(payload.get("org_role") or org_obj.get("rol") or "")
    explicit_role = payload.get("rootmesh_role")
    explicit_roles = payload.get("roles", [])

    assigned_role = "investigator"  # Default least-privilege role

    if explicit_role in ROLE_PERMISSIONS:
        assigned_role = explicit_role
    elif isinstance(explicit_roles, list) and any(r in ROLE_PERMISSIONS for r in explicit_roles):
        for candidate in ["admin", "responder", "analyst", "investigator"]:
            if candidate in explicit_roles:
                assigned_role = candidate
                break
    elif org_role in {"org:rootmesh_admin", "rootmesh:admin"}:
        assigned_role = "admin"
    elif org_role in {"org:admin", "admin", "org:responder", "responder"}:
        # SEPARATION OF DUTIES ENFORCEMENT:
        # Generic Clerk org:admin maps to RootMesh 'responder'.
        # A responder can investigate and propose containment, but CANNOT approve or execute.
        assigned_role = "responder"
    elif org_role in {"org:analyst", "analyst"}:
        assigned_role = "analyst"
    elif org_role in {"org:member", "member", "org:investigator", "investigator"}:
        assigned_role = "investigator"

    permissions = sorted(list(ROLE_PERMISSIONS.get(assigned_role, ROLE_PERMISSIONS["investigator"])))

    sub = str(payload.get("sub", "unknown"))
    username = str(payload.get("username") or payload.get("email") or sub)
    email = str(payload.get("email") or (f"{username}@company.com" if "@" not in username else username))

    return SecurityPrincipal(
        principal_id=sub,
        username=username,
        email=email,
        tenant_id=tenant_id,
        roles=[assigned_role],
        permissions=permissions,
        workspaces=[tenant_id],
    )


def _verify_legacy_dev_token(token: str) -> SecurityPrincipal:
    """
    Decodes and cryptographically verifies a legacy development access token.
    Disabled unconditionally in production mode.
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


def verify_access_token(token: str) -> SecurityPrincipal:
    """
    Decodes and cryptographically verifies an access token.
    Routes RS256 tokens to Clerk session verification.
    Rejects legacy HS256 tokens when Clerk authentication is configured.
    """
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: Invalid token ({type(e).__name__}).",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    alg = header.get("alg")
    if alg == "RS256":
        return verify_clerk_token(token)

    # If Clerk is configured on this node, reject legacy tokens
    if settings.clerk_jwks_url or settings.clerk_pem_public_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Legacy tokens are disabled. Clerk RS256 authentication required.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    return _verify_legacy_dev_token(token)


def create_test_clerk_token(
    sub: str = "user_2test123",
    username: str = "alex.rivera",
    email: str = "alex.rivera@company.com",
    org_id: str = "org_2secops_alpha",
    org_role: str = "org:admin",
    rootmesh_role: Optional[str] = None,
    azp: str = "http://localhost:3000",
    issuer: Optional[str] = None,
    private_key: Optional[Any] = None,
    expires_in_seconds: int = 3600,
    nbf_offset_seconds: int = 0,
    custom_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Helper to generate signed RS256 Clerk session tokens for test and validation suites."""
    now = int(time.time())
    payload: Dict[str, Any] = {
        "sub": sub,
        "iss": issuer or settings.clerk_issuer or "https://clerk.rootmesh.security",
        "azp": azp,
        "exp": now + expires_in_seconds,
        "iat": now,
        "nbf": now + nbf_offset_seconds,
        "sid": f"sess_{uuid.uuid4().hex[:16]}",
        "org_id": org_id,
        "org_role": org_role,
        "username": username,
        "email": email,
    }
    if rootmesh_role:
        payload["rootmesh_role"] = rootmesh_role
    if custom_claims:
        payload.update(custom_claims)

    if not private_key:
        raise ValueError("A private RSA key must be provided to sign the test token.")

    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-clerk-kid-1"})


# ──────────────────────────────────────────────
# FastAPI Dependency Injection Boundary
# ──────────────────────────────────────────────

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_principal(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> SecurityPrincipal:
    """
    Default-to-deny authentication dependency.
    Extracts Bearer token from HTTP Authorization header and cryptographically verifies claims.
    Unconditionally rejects unauthenticated requests with HTTP 401 Unauthorized.
    Never assigns an automatic admin, responder, or other privileged principal.
    """
    if not credentials or not credentials.credentials:
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
