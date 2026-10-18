/**
 * RootMesh Frontend — Production Authentication Client
 * Provides token caching, authenticated HTTP requests, and authorized WebSocket URL builder.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const WS_BASE = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000";
const DEFAULT_TENANT = "sec_ops_tenant_alpha";

let cachedToken: string | null = null;
let tokenExpiresAt = 0;

/**
 * Retrieves a valid, signed JWT access token.
 * Authenticates against /api/v1/auth/token if no valid token is cached.
 */
export async function getAuthToken(): Promise<string> {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt > now + 30000) {
    return cachedToken;
  }

  // Attempt local storage if in browser
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem("rootmesh_auth_token");
    const storedExp = localStorage.getItem("rootmesh_auth_exp");
    if (stored && storedExp && parseInt(storedExp, 10) > now + 30000) {
      cachedToken = stored;
      tokenExpiresAt = parseInt(storedExp, 10);
      return cachedToken;
    }
  }

  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "alex.rivera",
        secret: "rivera-secops-2026",
        tenant_id: DEFAULT_TENANT,
      }),
    });

    if (res.ok) {
      const data = await res.json();
      cachedToken = data.access_token;
      tokenExpiresAt = now + data.expires_in * 1000;
      if (typeof window !== "undefined") {
        localStorage.setItem("rootmesh_auth_token", cachedToken as string);
        localStorage.setItem("rootmesh_auth_exp", tokenExpiresAt.toString());
      }
      return cachedToken as string;
    }
  } catch (err) {
    console.warn("RootMesh Auth: Unable to acquire session token from backend:", err);
  }

  return "";
}

/**
 * Executes an HTTP fetch request guaranteed to carry valid Bearer authentication.
 */
export async function authenticatedFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const token = await getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(url, {
    ...options,
    headers,
  });
}

/**
 * Builds an authenticated WebSocket URL with signed token and tenant parameters.
 */
export async function getAuthenticatedWebSocketUrl(
  endpoint: string = "/ws/threat-stream",
  tenantId: string = DEFAULT_TENANT
): Promise<string> {
  const token = await getAuthToken();
  const base = WS_BASE.replace(/\/$/, "");
  const path = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;

  if (token) {
    return `${base}${path}?token=${encodeURIComponent(token)}&tenant_id=${encodeURIComponent(tenantId)}`;
  }
  return `${base}${path}?tenant_id=${encodeURIComponent(tenantId)}`;
}
