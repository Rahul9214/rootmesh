/**
 * RootMesh Frontend — Clerk Authentication & Initialization Regression Suite
 * Tests Clerk initialization race conditions, token refresh, sign-out,
 * organization switching, and React effect re-execution protections.
 */
import test, { describe, beforeEach, afterEach } from "node:test";
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";

import {
  setClerkTokenGetter,
  setClerkSignOut,
  setClerkLoaded,
  isClerkLoaded,
  isClerkConfigured,
  isDevPreviewAllowed,
  resetAuthStateForTesting,
  refreshBackendPrincipal,
  syncClerkSession,
  onAuthStateChanged,
  getCurrentPrincipal,
  getAuthToken,
  logout,
  authenticatedFetch,
  getWebSocketUrl,
  getAuthenticatedWebSocketUrl,
  sendWebSocketAuth,
} from "../lib/auth.ts";
import { threatStream } from "../lib/threatStream.ts";

describe("RootMesh Clerk Authentication Lifecycle & Regression Suite", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    resetAuthStateForTesting();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    resetAuthStateForTesting();
  });

  test("Requirement 1: Protected API requests wait for Clerk initialization before dispatching", async () => {
    let fetchCalled = false;
    let authHeaderSent: string | null = null;

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      fetchCalled = true;
      const headers = new Headers(init?.headers);
      authHeaderSent = headers.get("Authorization");
      return new Response(JSON.stringify([{ incident_id: "inc-18c2b368" }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof globalThis.fetch;

    // Clerk is NOT yet loaded
    assert.strictEqual(isClerkLoaded(), false);

    // Provide token getter that will succeed once initialized
    setClerkTokenGetter(async () => "clerk_valid_jwt_alpha");

    // Initiate request before Clerk has loaded
    const fetchPromise = authenticatedFetch("http://localhost:8000/api/v1/incident/sec_ops_tenant_alpha?limit=1");

    // Ensure request has not completed immediately without waiting
    assert.strictEqual(fetchCalled, false, "Request must not dispatch before Clerk finishes initializing");

    // Simulate delayed Clerk initialization completion after 40ms
    await new Promise((resolve) => setTimeout(resolve, 40));
    setClerkLoaded(true);

    const response = await fetchPromise;
    assert.strictEqual(response.status, 200);
    assert.strictEqual(fetchCalled, true);
    assert.strictEqual(authHeaderSent, "Bearer clerk_valid_jwt_alpha", "Bearer token must be attached");

    const data = await response.json();
    assert.strictEqual(data[0].incident_id, "inc-18c2b368");
  });

  test("Requirement 2 & 5: Missing token / Signed-out state dispatches cleanly without crash or loop", async () => {
    let callCount = 0;
    globalThis.fetch = (async () => {
      callCount++;
      return new Response(JSON.stringify({ detail: "Not authenticated: Missing Bearer authorization token." }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof globalThis.fetch;

    // Clerk is loaded, but user is signed out (token getter returns null)
    setClerkLoaded(true);
    setClerkTokenGetter(async () => null);

    const response = await authenticatedFetch("http://localhost:8000/api/v1/incident/sec_ops_tenant_alpha?limit=1");
    assert.strictEqual(response.status, 401);
    assert.strictEqual(callCount, 1, "Should not loop indefinitely when no token is available");
    assert.strictEqual(getCurrentPrincipal(), null);
  });

  test("Requirement 3: HTTP 401 triggers token refresh and single retry with fresh token", async () => {
    let tokenVersion = 1;
    let attempts = 0;
    const receivedAuthHeaders: (string | null)[] = [];

    setClerkLoaded(true);
    setClerkTokenGetter(async (options) => {
      if (options?.skipCache) {
        tokenVersion = 2;
        return "clerk_refreshed_jwt_v2";
      }
      return tokenVersion === 1 ? "clerk_expired_jwt_v1" : "clerk_refreshed_jwt_v2";
    });

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      attempts++;
      const headers = new Headers(init?.headers);
      const auth = headers.get("Authorization");
      receivedAuthHeaders.push(auth);

      if (auth === "Bearer clerk_expired_jwt_v1") {
        return new Response(JSON.stringify({ detail: "Token expired" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify([{ incident_id: "inc-18c2b368", status: "INVESTIGATED" }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof globalThis.fetch;

    const res = await authenticatedFetch("http://localhost:8000/api/v1/incident/sec_ops_tenant_alpha?limit=1");
    assert.strictEqual(res.status, 200, "Refreshed request should succeed with 200");
    assert.strictEqual(attempts, 2, "Should attempt initial fetch + exactly 1 refreshed retry");
    assert.deepStrictEqual(receivedAuthHeaders, [
      "Bearer clerk_expired_jwt_v1",
      "Bearer clerk_refreshed_jwt_v2",
    ]);

    const data = await res.json();
    assert.strictEqual(data[0].incident_id, "inc-18c2b368");
  });

  test("Requirement 4 & 5: Sign-out clears cached principal, notifies listeners, and resets token", async () => {
    let lastNotifiedPrincipal: unknown = "initial";
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "mock_token_for_user");
    setClerkSignOut(async () => {});

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({
        principal_id: "user_alpha_123",
        username: "alpha_analyst",
        email: "alpha@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["secops_analyst"],
        permissions: ["threat:read", "containment:propose"],
        workspaces: ["alpha_ws"],
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof globalThis.fetch;

    onAuthStateChanged((p) => {
      lastNotifiedPrincipal = p;
    });

    // Populate authenticated state
    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_alpha_123",
      username: "alpha_analyst",
      orgId: "org_alpha",
    });

    await refreshBackendPrincipal(true);
    const active = getCurrentPrincipal();
    assert.ok(active);
    assert.strictEqual(active?.tenant_id, "sec_ops_tenant_alpha");

    // Perform logout
    await logout();

    assert.strictEqual(getCurrentPrincipal(), null, "Principal must be cleared on logout");
    assert.strictEqual(lastNotifiedPrincipal, null, "Listeners must be notified with null on logout");

    // Subsequent token calls return empty
    setClerkTokenGetter(async () => null);
    const tokenAfter = await getAuthToken({ waitForReady: false });
    assert.strictEqual(tokenAfter, "");
  });

  test("Requirement 4: Organization switching immediately clears tenant to prevent cross-tenant state leakage", async () => {
    setClerkLoaded(true);
    let activeToken = "token_org_alpha";
    setClerkTokenGetter(async () => activeToken);

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      const auth = headers.get("Authorization");
      if (auth === "Bearer token_org_alpha") {
        return new Response(JSON.stringify({
          principal_id: "user_multi_org",
          username: "multi_user",
          email: "multi@rootmesh.security",
          tenant_id: "sec_ops_tenant_alpha",
          roles: ["analyst"],
          permissions: ["threat:read"],
          workspaces: ["alpha"],
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      } else if (auth === "Bearer token_org_beta") {
        return new Response(JSON.stringify({
          principal_id: "user_multi_org",
          username: "multi_user",
          email: "multi@rootmesh.security",
          tenant_id: "sec_ops_tenant_beta",
          roles: ["admin"],
          permissions: ["threat:read", "containment:execute"],
          workspaces: ["beta"],
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ detail: "Forbidden" }), { status: 403 });
    }) as typeof globalThis.fetch;

    // 1. Initial login with org_alpha
    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_multi_org",
      username: "multi_user",
      orgId: "org_alpha",
    });

    await refreshBackendPrincipal(true);
    assert.strictEqual(getCurrentPrincipal()?.tenant_id, "sec_ops_tenant_alpha");

    // 2. Switch to org_beta
    activeToken = "token_org_beta";
    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_multi_org",
      username: "multi_user",
      orgId: "org_beta",
    });

    // CRITICAL: Tenant must be cleared IMMEDIATELY on orgId change before backend verification completes
    assert.strictEqual(
      getCurrentPrincipal()?.tenant_id,
      "",
      "Tenant ID must be reset to empty immediately on org switch to avoid cross-tenant leakage"
    );

    // 3. Complete backend principal verification for org_beta
    await refreshBackendPrincipal(true);
    assert.strictEqual(getCurrentPrincipal()?.tenant_id, "sec_ops_tenant_beta");
    assert.deepStrictEqual(getCurrentPrincipal()?.roles, ["admin"]);
  });

  test("Requirement 4 & 6: React effect re-execution deduplicates concurrent principal verification", async () => {
    let authMeCalls = 0;
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "valid_session_token");

    globalThis.fetch = (async () => {
      authMeCalls++;
      // Simulate slight network latency
      await new Promise((r) => setTimeout(r, 20));
      return new Response(JSON.stringify({
        principal_id: "user_strict_mode",
        username: "strict_tester",
        email: "strict@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["analyst"],
        permissions: ["threat:read"],
        workspaces: ["ws_strict"],
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_strict_mode",
      orgId: "org_alpha",
    });

    // Simulate 3 concurrent component mounts / effects (e.g., StrictMode)
    const [p1, p2, p3] = await Promise.all([
      refreshBackendPrincipal(false),
      refreshBackendPrincipal(false),
      refreshBackendPrincipal(false),
    ]);

    assert.strictEqual(p1?.tenant_id, "sec_ops_tenant_alpha");
    assert.strictEqual(p2?.tenant_id, "sec_ops_tenant_alpha");
    assert.strictEqual(p3?.tenant_id, "sec_ops_tenant_alpha");
    assert.strictEqual(authMeCalls, 1, "Concurrent principal refreshes must be deduplicated to a single HTTP request");
  });

  test("Requirement 4: Out-of-order stale responses are safely discarded", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "fast_token");

    let reqCount = 0;
    globalThis.fetch = (async () => {
      reqCount++;
      const currentReq = reqCount;
      if (currentReq === 1) {
        // Slow response for first request (50ms)
        await new Promise((r) => setTimeout(r, 50));
        return new Response(JSON.stringify({
          principal_id: "stale_user",
          username: "stale",
          email: "stale@rootmesh.security",
          tenant_id: "stale_tenant_old",
          roles: [],
          permissions: [],
          workspaces: [],
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      } else {
        // Fast response for second request (10ms)
        await new Promise((r) => setTimeout(r, 10));
        return new Response(JSON.stringify({
          principal_id: "fresh_user",
          username: "fresh",
          email: "fresh@rootmesh.security",
          tenant_id: "fresh_tenant_new",
          roles: ["admin"],
          permissions: ["threat:read"],
          workspaces: [],
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
    }) as typeof globalThis.fetch;

    // Trigger slow request and allow its network dispatch to initiate
    const slowPromise = refreshBackendPrincipal(true);
    await new Promise((r) => setTimeout(r, 5));

    // Trigger faster second request while first is in-flight
    const fastPromise = refreshBackendPrincipal(true);

    await Promise.all([slowPromise, fastPromise]);

    // The active principal must be the latest request (fresh_tenant_new), never overwritten by the slow stale response
    assert.strictEqual(getCurrentPrincipal()?.tenant_id, "fresh_tenant_new");
    assert.strictEqual(getCurrentPrincipal()?.username, "fresh");
  });

  test("Requirement 2: WebSocket URLs are clean and never contain query parameter secrets or tokens", async () => {
    // Both helpers must return clean URLs with no ?token=... or ?tenant_id=...
    const url1 = getWebSocketUrl("/ws/threat-stream");
    const url2 = await getAuthenticatedWebSocketUrl("/ws/threat-stream", "sec_ops_tenant_alpha");

    assert.strictEqual(url1.includes("?"), false, "WebSocket URL must never contain query parameters");
    assert.strictEqual(url2.includes("?"), false, "Authenticated WebSocket URL must never contain query parameters");
    assert.strictEqual(url1.endsWith("/ws/threat-stream"), true);
    assert.strictEqual(url2.endsWith("/ws/threat-stream"), true);
  });

  test("Requirement 2 & 3: sendWebSocketAuth transmits in-band auth over established WebSocket", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "mock_signed_clerk_jwt_payload");

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({
        principal_id: "user_ws_test",
        username: "alex.rivera",
        email: "alex@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["admin"],
        permissions: ["threat:read"],
        workspaces: ["alpha"],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_ws_test",
      username: "alex.rivera",
      orgId: "org_alpha",
    });

    const sentMessages: string[] = [];
    const mockWs = {
      readyState: 1, // WebSocket.OPEN
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    // Dispatch auth with explicit tenant matching verified principal
    const success = await sendWebSocketAuth(mockWs, "sec_ops_tenant_alpha");
    assert.strictEqual(success, true, "sendWebSocketAuth should return true on success");
    assert.strictEqual(sentMessages.length, 1);

    const parsed = JSON.parse(sentMessages[0]);
    assert.strictEqual(parsed.type, "auth");
    assert.strictEqual(parsed.token, "mock_signed_clerk_jwt_payload");
    assert.strictEqual(parsed.tenant_id, "sec_ops_tenant_alpha");
  });

  test("Requirement 2 & 3: sendWebSocketAuth fails gracefully when signed out or socket not open", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => null);

    const sentMessages: string[] = [];
    const mockWs = {
      readyState: 1, // WebSocket.OPEN
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    // 1. Signed out / missing token
    const signedOutResult = await sendWebSocketAuth(mockWs, "sec_ops_tenant_alpha");
    assert.strictEqual(signedOutResult, false, "Should return false when user is signed out");
    assert.strictEqual(sentMessages.length, 0);

    // 2. Token present but WebSocket not open
    setClerkTokenGetter(async () => "valid_token");
    const closedWs = {
      readyState: 0, // WebSocket.CONNECTING
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    const notOpenResult = await sendWebSocketAuth(closedWs, "sec_ops_tenant_alpha");
    assert.strictEqual(notOpenResult, false, "Should return false when WebSocket is not OPEN");
    assert.strictEqual(sentMessages.length, 0);
  });

  test("Requirement 4: sendWebSocketAuth strictly overrides unverified tenant parameter with Clerk-verified tenant identity", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "token_alpha_verified");

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({
        principal_id: "user_verified_alpha",
        username: "alpha_analyst",
        email: "analyst@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["analyst"],
        permissions: ["threat:read"],
        workspaces: ["alpha"],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_verified_alpha",
      username: "alpha_analyst",
      orgId: "org_alpha",
    });

    await refreshBackendPrincipal(true);
    assert.strictEqual(getCurrentPrincipal()?.tenant_id, "sec_ops_tenant_alpha");

    const sentMessages: string[] = [];
    const mockWs = {
      readyState: 1, // WebSocket.OPEN
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    // Caller attempts to pass an unverified rogue tenant parameter
    const sent = await sendWebSocketAuth(mockWs, "unverified_tenant_rogue");
    assert.strictEqual(sent, true);
    assert.strictEqual(sentMessages.length, 1);

    const parsed = JSON.parse(sentMessages[0]);
    // Must be overridden to the verified tenant "sec_ops_tenant_alpha"
    assert.strictEqual(parsed.tenant_id, "sec_ops_tenant_alpha", "Must enforce verified Clerk tenant identity");
    assert.strictEqual(parsed.token, "token_alpha_verified");
  });

  test("Requirement 4 & 5: ThreatStream rejects mismatched auth_ok and strictly enforces verified Clerk tenant", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "token_alpha_verified");

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({
        principal_id: "user_verified_alpha",
        username: "alpha_analyst",
        email: "analyst@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["analyst"],
        permissions: ["threat:read"],
        workspaces: ["alpha"],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_verified_alpha",
      username: "alpha_analyst",
      orgId: "org_alpha",
    });

    await refreshBackendPrincipal(true);

    threatStream.disconnect();
    // Attempting to set an unverified rogue tenant when verified tenant is sec_ops_tenant_alpha
    threatStream.setTenant("rogue_tenant_xyz");
    assert.strictEqual(
      threatStream.getTenant(),
      "sec_ops_tenant_alpha",
      "threatStream must prioritize verified Clerk tenant"
    );

    // Mismatched auth_ok must be rejected
    threatStream.handleRawMessage({
      type: "auth_ok",
      tenant_id: "rogue_tenant_xyz",
    });
    assert.notStrictEqual(threatStream.getStatus(), "live", "Mismatched auth_ok must not activate live status");

    // Matched auth_ok must be accepted
    threatStream.handleRawMessage({
      type: "auth_ok",
      tenant_id: "sec_ops_tenant_alpha",
    });
    assert.strictEqual(threatStream.getStatus(), "live", "Matched auth_ok must transition status to live");

    threatStream.disconnect();
    threatStream.setTenant(null);
  });

  test("Step 3BF.2 Requirement 1 & 2: Missing verified principal aborts auth and never falls back to caller-supplied tenant", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "valid_token_but_unmapped_org");

    // Backend returns 403 or unmapped organization
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({
        detail: "Authorization failed: Organization not mapped to authorized tenant",
      }), { status: 403, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_unmapped",
      username: "unmapped_user",
      orgId: "org_unmapped",
    });

    const sentMessages: string[] = [];
    const mockWs = {
      readyState: 1, // WebSocket.OPEN
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    // Caller attempts to supply "sec_ops_tenant_alpha" while verified backend principal is missing/unmapped
    const result = await sendWebSocketAuth(mockWs, "sec_ops_tenant_alpha");
    assert.strictEqual(result, false, "Must return false when verified backend tenant is missing");
    assert.strictEqual(sentMessages.length, 0, "Must NEVER transmit an auth frame when verified principal is missing");
  });

  test("Step 3BF.2 Requirement 6: Mismatched caller-supplied tenant is overridden with verified backend principal tenant", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "token_alpha_verified");

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({
        principal_id: "user_alpha_verified",
        username: "alpha_user",
        email: "alpha@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["analyst"],
        permissions: ["threat:read"],
        workspaces: ["alpha"],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_alpha_verified",
      username: "alpha_user",
      orgId: "org_alpha",
    });

    const sentMessages: string[] = [];
    const mockWs = {
      readyState: 1,
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    // Caller supplies a rogue/mismatched tenant
    const result = await sendWebSocketAuth(mockWs, "sec_ops_tenant_beta_attacker");
    assert.strictEqual(result, true);
    assert.strictEqual(sentMessages.length, 1);

    const parsed = JSON.parse(sentMessages[0]);
    assert.strictEqual(parsed.tenant_id, "sec_ops_tenant_alpha", "Must enforce verified tenant over caller tenant");
  });

  test("Step 3BF.2 Requirement 3 & 6: Successful authentication after pending principal initialization", async () => {
    setClerkLoaded(true);
    setClerkTokenGetter(async () => "token_delayed_init");

    let fetchCalled = false;
    globalThis.fetch = (async () => {
      fetchCalled = true;
      return new Response(JSON.stringify({
        principal_id: "user_delayed",
        username: "delayed_user",
        email: "delayed@rootmesh.security",
        tenant_id: "sec_ops_tenant_alpha",
        roles: ["admin"],
        permissions: ["threat:read"],
        workspaces: ["alpha"],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;

    syncClerkSession({
      isLoaded: true,
      isSignedIn: true,
      userId: "user_delayed",
      username: "delayed_user",
      orgId: "org_alpha",
    });

    // Note: Principal has NOT yet been verified with backend, so tenant_id is empty/pending
    assert.strictEqual(Boolean(getCurrentPrincipal()?.tenant_id), false, "Tenant ID should initially be pending/empty");

    const sentMessages: string[] = [];
    const mockWs = {
      readyState: 1,
      send: (data: string) => {
        sentMessages.push(data);
      },
    } as unknown as WebSocket;

    // Call sendWebSocketAuth WITHOUT caller tenant — it must wait/resolve principal and send verified tenant
    const result = await sendWebSocketAuth(mockWs);
    assert.strictEqual(fetchCalled, true, "Must have triggered principal resolution");
    assert.strictEqual(result, true, "Authentication must succeed after principal initialization");
    assert.strictEqual(sentMessages.length, 1);

    const parsed = JSON.parse(sentMessages[0]);
    assert.strictEqual(parsed.type, "auth");
    assert.strictEqual(parsed.token, "token_delayed_init");
    assert.strictEqual(parsed.tenant_id, "sec_ops_tenant_alpha");
  });

  test("PR #9 Requirement 1 & 2: isClerkConfigured dynamically reports configuration status without fake credentials", () => {
    const origKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
    const origServerKey = process.env.CLERK_PUBLISHABLE_KEY;

    try {
      delete process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
      delete process.env.CLERK_PUBLISHABLE_KEY;
      assert.strictEqual(isClerkConfigured(), false, "Must return false when publishable key is unset");

      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = "pk_test_prod_credential_verification";
      assert.strictEqual(isClerkConfigured(), true, "Must return true when NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY is present");

      delete process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
      process.env.CLERK_PUBLISHABLE_KEY = "pk_test_server_credential_verification";
      assert.strictEqual(isClerkConfigured(), true, "Must return true when CLERK_PUBLISHABLE_KEY is present");
    } finally {
      if (origKey !== undefined) {
        process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = origKey;
      } else {
        delete process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
      }
      if (origServerKey !== undefined) {
        process.env.CLERK_PUBLISHABLE_KEY = origServerKey;
      } else {
        delete process.env.CLERK_PUBLISHABLE_KEY;
      }
    }
  });

  test("PR #9 Requirement 1 & 6: Top-level page entry point never conditionally invokes React hooks", () => {
    const pageSrc = fs.readFileSync(path.join(process.cwd(), "app", "page.tsx"), "utf8");

    // HomePage default export must not call Clerk hooks directly
    const homePageIdx = pageSrc.indexOf("export default function HomePage()");
    assert.ok(homePageIdx !== -1, "HomePage must be exported as default function");
    const homePageCode = pageSrc.slice(homePageIdx);

    assert.ok(!homePageCode.includes("useAuth("), "HomePage entry point must not call useAuth directly");
    assert.ok(!homePageCode.includes("useUser("), "HomePage entry point must not call useUser directly");
    assert.ok(!homePageCode.includes("useOrganization("), "HomePage entry point must not call useOrganization directly");
    assert.ok(!homePageCode.includes("useClerk("), "HomePage entry point must not call useClerk directly");

    // Must cleanly branch between unconfigured and authenticated components
    assert.ok(homePageCode.includes("UnconfiguredLandingApp"), "HomePage must render UnconfiguredLandingApp when unconfigured");
    assert.ok(homePageCode.includes("ClerkAuthenticatedApp"), "HomePage must render ClerkAuthenticatedApp when configured");

    // ClerkAuthenticatedApp must encapsulate all Clerk hooks unconditionally
    const clerkAppMatch = pageSrc.match(/function ClerkAuthenticatedApp()[^{]*{/);
    assert.ok(clerkAppMatch, "ClerkAuthenticatedApp must exist as separate component");
  });

  test("PR #9 Requirement 2 & 4: Unconfigured mode renders accessible authentication-unavailable state rather than nonfunctional buttons", () => {
    const landingSrc = fs.readFileSync(path.join(process.cwd(), "components", "PublicLandingExperience.tsx"), "utf8");
    const pageSrc = fs.readFileSync(path.join(process.cwd(), "app", "page.tsx"), "utf8");

    // PublicLandingExperience must support unconfigured mode without mounting SignInButton
    assert.ok(landingSrc.includes("isClerkConfigured"), "PublicLandingExperience must accept isClerkConfigured prop");
    assert.ok(landingSrc.includes("Authentication Unavailable"), "PublicLandingExperience must provide accessible disabled auth state");
    assert.ok(landingSrc.includes('aria-disabled="true"'), "PublicLandingExperience must set aria-disabled on unavailable CTA");
    assert.ok(landingSrc.includes("cursor-not-allowed"), "PublicLandingExperience must set cursor-not-allowed on unavailable CTA");

    // TopNavbar must display accessible Auth Unavailable pill when Clerk is unconfigured
    assert.ok(pageSrc.includes("Auth Unavailable"), "TopNavbar must provide Auth Unavailable pill");
    assert.ok(pageSrc.includes('role="status"'), "TopNavbar unavailable state must have role=status");
    assert.ok(pageSrc.includes("isClerkConfigured ? ("), "TopNavbar must guard SignInButton behind isClerkConfigured");
  });

  test("PR #9 Requirement 5: Configured mode preserves complete multi-tenant Clerk flows", () => {
    const pageSrc = fs.readFileSync(path.join(process.cwd(), "app", "page.tsx"), "utf8");

    // Must preserve full sign-in and org management in ClerkAuthenticatedApp
    assert.ok(pageSrc.includes("<OrganizationSwitcher"), "Must preserve OrganizationSwitcher in TopNavbar");
    assert.ok(pageSrc.includes("<UserButton"), "Must preserve UserButton in TopNavbar");
    assert.ok(pageSrc.includes("syncClerkSession"), "Must preserve session synchronization with backend");
    assert.ok(pageSrc.includes("onAuthStateChanged"), "Must preserve authenticated principal subscription");
    assert.ok(pageSrc.includes("isClerkConfigured={true}"), "ClerkAuthenticatedApp must explicitly pass configured mode");
  });

  test("PR #9 Security Hardening: isDevPreviewAllowed strictly enforces production denial, loopback restriction, and explicit opt-in", () => {
    const origNodeEnv = process.env.NODE_ENV;
    const origDevPreview = process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW;
    const origAllowPreview = process.env.NEXT_PUBLIC_ALLOW_DEV_PREVIEW;

    try {
      // 1. Production Denial: Preview is unconditionally forbidden even with opt-in and localhost hostname
      (process.env as Record<string, string | undefined>).NODE_ENV = "production";
      process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW = "true";
      process.env.NEXT_PUBLIC_ALLOW_DEV_PREVIEW = "true";
      assert.strictEqual(isDevPreviewAllowed("localhost"), false, "Production must strictly deny preview on localhost");
      assert.strictEqual(isDevPreviewAllowed("127.0.0.1"), false, "Production must strictly deny preview on 127.0.0.1");
      assert.strictEqual(isDevPreviewAllowed(), false, "Production must deny preview without hostname");

      // 2. Non-development Denial: Any environment other than 'development' (e.g. test) must fail-closed
      (process.env as Record<string, string | undefined>).NODE_ENV = "test";
      assert.strictEqual(isDevPreviewAllowed("localhost"), false, "Test environment must strictly deny preview");

      // 3. Missing or Disabled Opt-In in Development:
      (process.env as Record<string, string | undefined>).NODE_ENV = "development";
      delete process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW;
      delete process.env.NEXT_PUBLIC_ALLOW_DEV_PREVIEW;
      assert.strictEqual(isDevPreviewAllowed("localhost"), false, "Development must deny preview without explicit opt-in");

      process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW = "false";
      assert.strictEqual(isDevPreviewAllowed("localhost"), false, "Development must deny preview when flag is false");

      process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW = "";
      assert.strictEqual(isDevPreviewAllowed("localhost"), false, "Development must deny preview when flag is empty");

      // 4. Non-Loopback Hostname Denial in Development (Even with opt-in enabled):
      process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW = "true";
      assert.strictEqual(isDevPreviewAllowed("rootmesh.security"), false, "Must deny preview on non-loopback domain");
      assert.strictEqual(isDevPreviewAllowed("192.168.1.100"), false, "Must deny preview on private LAN IP");
      assert.strictEqual(isDevPreviewAllowed("10.0.0.1"), false, "Must deny preview on class A private IP");
      assert.strictEqual(isDevPreviewAllowed("example.com"), false, "Must deny preview on public domain");
      assert.strictEqual(isDevPreviewAllowed(""), false, "Must deny preview on empty hostname");
      assert.strictEqual(isDevPreviewAllowed(undefined), false, "Must deny preview on undefined hostname (SSR)");

      // 5. Localhost / 127.0.0.1 Development Opt-In Permitted:
      assert.strictEqual(isDevPreviewAllowed("localhost"), true, "Development permits preview on localhost with opt-in");
      assert.strictEqual(isDevPreviewAllowed("127.0.0.1"), true, "Development permits preview on 127.0.0.1 with opt-in");

      process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW = "1";
      assert.strictEqual(isDevPreviewAllowed("localhost"), true, "Development permits preview with flag=1");

      delete process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW;
      process.env.NEXT_PUBLIC_ALLOW_DEV_PREVIEW = "true";
      assert.strictEqual(isDevPreviewAllowed("localhost"), true, "Development permits preview with allow flag");
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = origNodeEnv;
      if (origDevPreview !== undefined) {
        process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW = origDevPreview;
      } else {
        delete process.env.NEXT_PUBLIC_ENABLE_DEV_PREVIEW;
      }
      if (origAllowPreview !== undefined) {
        process.env.NEXT_PUBLIC_ALLOW_DEV_PREVIEW = origAllowPreview;
      } else {
        delete process.env.NEXT_PUBLIC_ALLOW_DEV_PREVIEW;
      }
    }
  });

  test("PR #9 Security Hardening: Preview query parameters cannot activate operational dashboard or synthetic principal in production", () => {
    const pageSrc = fs.readFileSync(path.join(process.cwd(), "app", "page.tsx"), "utf8");

    // Must import and invoke isDevPreviewAllowed with loopback window hostname
    assert.ok(pageSrc.includes("isDevPreviewAllowed"), "page.tsx must import isDevPreviewAllowed");
    assert.ok(pageSrc.includes("isDevPreviewAllowed(window.location.hostname)"), "page.tsx must pass window.location.hostname to isDevPreviewAllowed");

    // Strict separation: isAuthorized must strictly depend on verified Clerk state, NEVER isPreview
    assert.ok(pageSrc.includes("const isAuthorized = Boolean(isSignedIn && organization && principal?.tenant_id);"), "isAuthorized must strictly require genuine Clerk auth, org, and tenant");
    assert.ok(!pageSrc.includes("isAuthorized = isPreview ||"), "isAuthorized must NEVER conflate isPreview");

    // TopNavbar must receive genuine isSignedIn boolean, not (isSignedIn || isPreview)
    assert.ok(pageSrc.includes("isSignedIn={Boolean(isSignedIn)}"), "TopNavbar must receive genuine isSignedIn state");

    // Must never assign fake tenant or RBAC privileges to dev-preview principal
    assert.ok(!pageSrc.includes('"tenant-rootmesh"'), "page.tsx must not assign synthetic tenant-rootmesh");
    assert.ok(!pageSrc.includes('"ws-production"'), "page.tsx must not assign production workspace in preview");
    assert.ok(pageSrc.includes('tenant_id: ""'), "dev-preview principal must have empty tenant_id");
    assert.ok(pageSrc.includes("roles: []"), "dev-preview principal must have zero RBAC roles");
    assert.ok(pageSrc.includes("permissions: []"), "dev-preview principal must have zero RBAC permissions");
    assert.ok(pageSrc.includes("workspaces: []"), "dev-preview principal must have zero workspaces");

    // TopNavbar must not display OrganizationSwitcher to preview viewer
    assert.ok(pageSrc.includes("isSignedIn && !isPreview ? ("), "OrganizationSwitcher and UserButton must be hidden during preview");

    // TopNavbar must clearly label preview state as unverified local simulation
    assert.ok(pageSrc.includes("Development Preview Simulation (Unverified)"), "TopNavbar tooltip must label preview unverified simulation");
    assert.ok(pageSrc.includes("Local Dev Simulation (Unverified)"), "TopNavbar badge must label preview local dev simulation");

    // Operational dashboard must render prominent presentation-only banner
    assert.ok(pageSrc.includes("LOCAL DEV SIMULATION (UNVERIFIED):"), "Dashboard must render local dev simulation banner in preview");
    assert.ok(pageSrc.includes("Presentation Only"), "Dashboard banner must explicitly declare Presentation Only");
  });

  test("PR #9 Security Hardening: Public landing-page walkthrough remains fully functional and accessible without preview access", () => {
    const landingSrc = fs.readFileSync(path.join(process.cwd(), "components", "PublicLandingExperience.tsx"), "utf8");
    const walkthroughSrc = fs.readFileSync(path.join(process.cwd(), "components", "ProductWalkthroughReplay.tsx"), "utf8");

    // PublicLandingExperience must feature interactive walkthrough link
    assert.ok(landingSrc.includes('href="#product-walkthrough"'), "Public landing must provide anchor link to walkthrough");
    assert.ok(landingSrc.includes("<ProductWalkthroughReplay />") || landingSrc.includes("<ProductWalkthroughReplay"), "Public landing must render ProductWalkthroughReplay");

    // Walkthrough replay must operate completely client-side without backend calls
    assert.ok(walkthroughSrc.includes("Asset Selected"), "Walkthrough must contain 5 stages");
    assert.ok(walkthroughSrc.includes("Human Review Required"), "Walkthrough must explain human governance");
    assert.ok(!walkthroughSrc.includes("fetch("), "Walkthrough must not trigger network requests");
  });
});
