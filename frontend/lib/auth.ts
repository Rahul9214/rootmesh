/**
 * RootMesh Frontend — Clerk B2B Authentication & Authorization Client
 * Integrates official Clerk session tokens with RootMesh backend APIs and WebSockets.
 *
 * Strictly zero hardcoded credentials, zero client-side password handling,
 * and zero server secret exposure in client bundles.
 */

export interface PrincipalInfo {
  principal_id: string;
  username: string;
  email: string;
  tenant_id: string;
  roles: string[];
  permissions: string[];
  workspaces: string[];
}

export function getApiBase(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL.replace(/\/$/, "");
  }
  if (typeof window !== "undefined") {
    if (window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
      return window.location.origin;
    }
  }
  return "http://localhost:8000";
}

export function getWsBase(): string {
  if (process.env.NEXT_PUBLIC_WS_URL) {
    return process.env.NEXT_PUBLIC_WS_URL.replace(/\/$/, "");
  }
  if (typeof window !== "undefined") {
    if (window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      return `${proto}//${window.location.host}`;
    }
  }
  return "ws://localhost:8000";
}

// ──────────────────────────────────────────────
// Clerk Token Bridge & Reactive State
// ──────────────────────────────────────────────

type TokenGetter = (options?: { skipCache?: boolean }) => Promise<string | null>;
type SignOutFn = () => Promise<void>;

let clerkTokenGetter: TokenGetter | null = null;
let clerkSignOutFn: SignOutFn | null = null;
let cachedPrincipal: PrincipalInfo | null = null;
let cachedOrgId: string | null | undefined = undefined;
let clerkLoaded = false;
let clerkReadyWaiters: Array<() => void> = [];
const authListeners = new Set<(principal: PrincipalInfo | null) => void>();

function notifyListeners() {
  authListeners.forEach((fn) => {
    try {
      fn(cachedPrincipal);
    } catch {}
  });
}

/**
 * Explicitly marks Clerk as loaded and resolves any pending authorization waiters.
 */
export function setClerkLoaded(loaded: boolean): void {
  clerkLoaded = loaded;
  if (loaded && clerkReadyWaiters.length > 0) {
    const waiters = clerkReadyWaiters;
    clerkReadyWaiters = [];
    waiters.forEach((cb) => {
      try {
        cb();
      } catch {}
    });
  }
}

/**
 * Checks whether Clerk has completed its client-side initialization.
 */
export function isClerkLoaded(): boolean {
  if (clerkLoaded) return true;
  if (typeof window !== "undefined") {
    const clerk = (window as unknown as { Clerk?: { loaded?: boolean } }).Clerk;
    if (clerk?.loaded) {
      clerkLoaded = true;
      return true;
    }
    const hasClerkKey = Boolean(
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ||
      process.env.CLERK_PUBLISHABLE_KEY
    );
    if (!hasClerkKey) {
      return true;
    }
  }
  return false;
}

/**
 * Waits until Clerk initialization has resolved, or until timeout.
 */
export function waitForClerkReady(timeoutMs = 4000): Promise<boolean> {
  if (isClerkLoaded()) {
    return Promise.resolve(true);
  }
  return new Promise<boolean>((resolve) => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const onReady = () => {
      if (timer) clearTimeout(timer);
      resolve(true);
    };
    clerkReadyWaiters.push(onReady);
    timer = setTimeout(() => {
      const idx = clerkReadyWaiters.indexOf(onReady);
      if (idx !== -1) clerkReadyWaiters.splice(idx, 1);
      resolve(isClerkLoaded());
    }, timeoutMs);
  });
}

/**
 * Resets local authentication state (used for isolated test suites).
 */
export function resetAuthStateForTesting(): void {
  clerkTokenGetter = null;
  clerkSignOutFn = null;
  cachedPrincipal = null;
  cachedOrgId = undefined;
  clerkLoaded = false;
  clerkReadyWaiters = [];
  authListeners.clear();
  principalRequestId = 0;
  inFlightPrincipalPromise = null;
}

/**
 * Register official Clerk session token getter (invoked from Clerk React hook context).
 */
export function setClerkTokenGetter(getter: TokenGetter): void {
  clerkTokenGetter = getter;
}

/**
 * Register official Clerk sign out handler.
 */
export function setClerkSignOut(signOut: SignOutFn): void {
  clerkSignOutFn = signOut;
}

let principalRequestId = 0;
let inFlightPrincipalPromise: Promise<PrincipalInfo | null> | null = null;

/**
 * Asynchronously synchronizes the authoritative tenant context, roles, and permissions
 * from the backend `/api/v1/auth/me` endpoint using the verified Clerk bearer token.
 * Never uses organization slug heuristics or client-side wildcard mappings.
 * Automatically deduplicates concurrent calls and discards stale out-of-order responses.
 */
export async function refreshBackendPrincipal(force: boolean = false): Promise<PrincipalInfo | null> {
  if (inFlightPrincipalPromise && !force) {
    return inFlightPrincipalPromise;
  }

  const reqId = ++principalRequestId;

  const runRefresh = async (): Promise<PrincipalInfo | null> => {
    try {
      const token = await getAuthToken({ waitForReady: true });
      if (reqId !== principalRequestId) {
        return cachedPrincipal;
      }
      if (!token) {
        if (cachedPrincipal) {
          cachedPrincipal = null;
          notifyListeners();
        }
        return null;
      }
      const res = await fetch(`${getApiBase()}/api/v1/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (reqId !== principalRequestId) {
        return cachedPrincipal;
      }
      if (res.ok) {
        const backendPrincipal: PrincipalInfo = await res.json();
        cachedPrincipal = {
          principal_id: backendPrincipal.principal_id,
          username: backendPrincipal.username,
          email: backendPrincipal.email,
          tenant_id: backendPrincipal.tenant_id,
          roles: backendPrincipal.roles || [],
          permissions: backendPrincipal.permissions || [],
          workspaces: backendPrincipal.workspaces || [],
        };
        notifyListeners();
        return cachedPrincipal;
      } else if (res.status === 401) {
        // Session expired or unauthenticated
        cachedPrincipal = null;
        notifyListeners();
      } else if (res.status === 403) {
        // Unknown or unmapped organization rejected by backend
        if (cachedPrincipal) {
          cachedPrincipal = {
            ...cachedPrincipal,
            tenant_id: "",
            roles: [],
            permissions: [],
            workspaces: [],
          };
          notifyListeners();
        }
      }
    } catch (err) {
      console.warn("RootMesh Auth: Could not verify principal with backend:", err);
    } finally {
      if (inFlightPrincipalPromise === promise) {
        inFlightPrincipalPromise = null;
      }
    }
    return cachedPrincipal;
  };

  const promise = runRefresh();
  inFlightPrincipalPromise = promise;
  return promise;
}

/**
 * Synchronizes Clerk authenticated session and triggers backend principal verification.
 * Strictly avoids organization slug heuristics or client-generated tenant mappings.
 * Immediately clears active tenant ID on organization switch to prevent cross-tenant state leakage.
 */
export function syncClerkSession(sessionData: {
  isLoaded?: boolean;
  isSignedIn: boolean;
  userId?: string | null;
  username?: string | null;
  email?: string | null;
  orgId?: string | null;
  orgSlug?: string | null;
  orgRole?: string | null;
}): void {
  if (sessionData.isLoaded !== undefined) {
    setClerkLoaded(sessionData.isLoaded);
  }

  // Handle signed-out state: if Clerk has loaded and user is not signed in
  if (!sessionData.isSignedIn || !sessionData.userId) {
    cachedOrgId = null;
    if (cachedPrincipal !== null) {
      cachedPrincipal = null;
      notifyListeners();
    }
    return;
  }

  // Prevent cross-tenant state leakage on organization switch:
  // If orgId changed while signed in, immediately clear tenant_id and permissions
  // before async verification completes.
  const orgChanged = cachedOrgId !== undefined && cachedOrgId !== sessionData.orgId;
  cachedOrgId = sessionData.orgId ?? null;

  if (orgChanged && cachedPrincipal) {
    cachedPrincipal = {
      ...cachedPrincipal,
      tenant_id: "",
      roles: [],
      permissions: [],
      workspaces: [],
    };
    notifyListeners();
  }

  // Temporary local representation while awaiting backend verification from /api/v1/auth/me
  // Do NOT assign a default or unverified tenant identifier!
  if (!cachedPrincipal || cachedPrincipal.principal_id !== sessionData.userId) {
    cachedPrincipal = {
      principal_id: sessionData.userId,
      username: sessionData.username || sessionData.email || sessionData.userId,
      email: sessionData.email || `${sessionData.username || "user"}@rootmesh.security`,
      tenant_id: "",
      roles: [],
      permissions: [],
      workspaces: [],
    };
    notifyListeners();
  }

  // Authoritatively obtain verified tenant and permissions from backend
  if (sessionData.isLoaded !== false) {
    refreshBackendPrincipal(true);
  }
}

/**
 * Subscribe to authentication state changes.
 */
export function onAuthStateChanged(fn: (principal: PrincipalInfo | null) => void): () => void {
  authListeners.add(fn);
  fn(getCurrentPrincipal());
  return () => {
    authListeners.delete(fn);
  };
}

/**
 * Retrieves the currently authenticated principal profile, if any.
 */
export function getCurrentPrincipal(): PrincipalInfo | null {
  return cachedPrincipal;
}

/**
 * Retrieves a valid, signed Clerk session JWT.
 * Uses official Clerk SDK session getter or global Clerk instance.
 * By default, waits for Clerk initialization before attempting retrieval.
 */
export async function getAuthToken(options?: {
  skipCache?: boolean;
  waitForReady?: boolean;
  timeoutMs?: number;
}): Promise<string> {
  const shouldWait = options?.waitForReady ?? true;
  if (shouldWait && !isClerkLoaded()) {
    await waitForClerkReady(options?.timeoutMs ?? 4000);
  }

  if (clerkTokenGetter) {
    try {
      const token = await clerkTokenGetter({ skipCache: options?.skipCache });
      if (token) return token;
    } catch (err) {
      console.warn("RootMesh Auth: Error getting session token from getter:", err);
    }
  }

  // Fallback to window.Clerk session instance if available in browser
  if (typeof window !== "undefined") {
    try {
      const clerk = (window as unknown as {
        Clerk?: {
          session?: {
            getToken: (opts?: { skipCache?: boolean }) => Promise<string | null>;
          };
        };
      }).Clerk;
      if (clerk?.session?.getToken) {
        const token = await clerk.session.getToken({ skipCache: options?.skipCache });
        if (token) return token;
      }
    } catch (err) {
      console.warn("RootMesh Auth: Error getting session token from window.Clerk:", err);
    }
  }

  return "";
}

/**
 * Secure Sign-Out: invokes official Clerk sign out and resets local state.
 */
export async function logout(): Promise<void> {
  if (clerkSignOutFn) {
    try {
      await clerkSignOutFn();
    } catch {}
  } else if (typeof window !== "undefined") {
    try {
      const clerk = (window as unknown as { Clerk?: { signOut: () => Promise<void> } }).Clerk;
      if (clerk?.signOut) {
        await clerk.signOut();
      }
    } catch {}
  }

  cachedOrgId = null;
  cachedPrincipal = null;
  notifyListeners();
}

/**
 * Executes an HTTP fetch request carrying the active Clerk RS256 Bearer token.
 * Waits for Clerk initialization to complete before dispatching.
 * On HTTP 401 response, automatically attempts a single token refresh and retry.
 */
export async function authenticatedFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const token = await getAuthToken({ waitForReady: true });
  const headers = new Headers(options.headers || {});

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response = await fetch(url, {
    ...options,
    headers,
  });

  // Handle token refresh on 401 response (e.g. session expired or fresh token needed)
  if (response.status === 401) {
    try {
      const refreshedToken = await getAuthToken({ skipCache: true, waitForReady: true });
      if (refreshedToken && refreshedToken !== token) {
        const retryHeaders = new Headers(options.headers || {});
        retryHeaders.set("Authorization", `Bearer ${refreshedToken}`);
        response = await fetch(url, {
          ...options,
          headers: retryHeaders,
        });
      }
    } catch (refreshErr) {
      console.warn("RootMesh Auth: Token refresh on 401 response failed:", refreshErr);
    }
  }

  return response;
}

/**
 * Builds a clean, secure WebSocket URL without query parameters or exposed secrets.
 */
export function getWebSocketUrl(endpoint: string = "/ws/threat-stream"): string {
  const base = getWsBase();
  const path = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${base}${path}`;
}

/**
 * Builds a secure WebSocket URL.
 * Secrets are never sent via query parameters; authentication is performed
 * in-band using the initial message over the established connection.
 */
export async function getAuthenticatedWebSocketUrl(
  endpoint: string = "/ws/threat-stream",
  _tenantId?: string
): Promise<string> {
  void _tenantId;
  return getWebSocketUrl(endpoint);
}

/**
 * Transmits an in-band authentication message over an open WebSocket connection.
 * Zero secrets in URLs, subprotocols, or query strings.
 */
export async function sendWebSocketAuth(
  ws: WebSocket,
  tenantId?: string
): Promise<boolean> {
  const token = await getAuthToken({ waitForReady: true });
  if (!token) return false;

  let verifiedPrincipal = getCurrentPrincipal();
  // If principal is not yet loaded, attempt to initialize via existing bounded flow
  if (!verifiedPrincipal?.tenant_id) {
    verifiedPrincipal = await refreshBackendPrincipal(false);
  }

  const verifiedTenant = verifiedPrincipal?.tenant_id;
  // Strictly require verified tenant from backend principal.
  // Never fall back to a caller-supplied tenant when the verified principal is missing.
  if (!verifiedTenant) {
    console.warn(
      "RootMesh Auth: WebSocket authentication aborted — no verified backend tenant context available."
    );
    return false;
  }

  // If a caller passed a mismatched tenant, warn and enforce the verified tenant
  if (tenantId && tenantId !== verifiedTenant) {
    console.warn(
      `RootMesh Auth: Overriding unverified tenant '${tenantId}' with verified Clerk tenant '${verifiedTenant}'`
    );
  }

  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: "auth",
      token,
      tenant_id: verifiedTenant,
    }));
    return true;
  }
  return false;
}
