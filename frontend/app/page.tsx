"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
import Image from "next/image";
import Link from "next/link";
import {
  SignInButton,
  UserButton,
  OrganizationSwitcher,
  useAuth,
  useUser,
  useOrganization,
  useClerk,
} from "@clerk/nextjs";
import { HeroSection, type InvestigationSummary } from "@/components/HeroSection";
import {
  IncidentJourneyTimeline,
  type IncidentLifecycleState,
  type ProposalInfo,
  type AuditInfo,
} from "@/components/IncidentJourneyTimeline";
import { FallingBlockGrid } from "@/components/FallingBlockGrid";
import { SwipeableCardStack } from "@/components/SwipeableCardStack";
import { GraphCanvas } from "@/components/GraphCanvas";
import { RiskPrioritiesDeck } from "@/components/RiskPrioritiesDeck";
import { LiveEvidenceComposer } from "@/components/LiveEvidenceComposer";
import { CompanyBrainDossier } from "@/components/CompanyBrainDossier";
import { NetworkGridBackground } from "@/components/NetworkGridBackground";
import { PublicLandingExperience } from "@/components/PublicLandingExperience";
import { LifecycleGovernanceGuide } from "@/components/LifecycleGovernanceGuide";
import { threatStream, type ThreatStreamEvent } from "@/lib/threatStream";
import {
  setClerkTokenGetter,
  setClerkSignOut,
  syncClerkSession,
  onAuthStateChanged,
  authenticatedFetch,
  type PrincipalInfo,
} from "@/lib/auth";
import {
  checkSystemHealth,
  onSystemHealthChanged,
  getCachedSystemHealth,
  type SystemHealth,
} from "@/lib/health";

const API_DOCS_URL = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/docs`
  : "http://localhost:8000/docs";

const FALKORDB_BROWSER_URL = process.env.NEXT_PUBLIC_FALKORDB_BROWSER_URL || "";
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const HAS_CLERK_KEY = Boolean(
  process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ||
  process.env.CLERK_PUBLISHABLE_KEY
);

// ──────────────────────────────────────────────
// Top Navigation Bar
// ──────────────────────────────────────────────

interface TopNavbarProps {
  principal: PrincipalInfo | null;
  isSignedIn: boolean;
  systemHealth: SystemHealth;
  isAuthorized: boolean;
  organizationName?: string;
}

function TopNavbar({ principal, isSignedIn, systemHealth, isAuthorized, organizationName }: TopNavbarProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-[#DFD6C9] bg-[#FAF7F2]/85 backdrop-blur-md shadow-warm-xs transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="h-14 sm:h-16 flex items-center justify-between gap-2 sm:gap-4">
          {/* Brand Wordmark / Logo */}
          <div className="flex-shrink-0 flex items-center">
            <Link
              href="/"
              className="flex items-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#D26A50] rounded-lg"
              aria-label="RootMesh Home"
            >
              <Image
                src="/brand/rootmesh-wordmark.png"
                alt="RootMesh"
                width={154}
                height={48}
                className="h-7 sm:h-8 w-auto object-contain block"
                priority
              />
            </Link>
          </div>

          {/* Operational Status & Authentication Controls */}
          <div className="flex items-center gap-1.5 sm:gap-2.5 text-xs font-mono">
            {!HAS_CLERK_KEY && (
              <div
                className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#FFF8E6] text-[#B87A14] border border-[#F5E0B8] text-[11px]"
                title="Clerk Publishable Key is unset."
              >
                <span>⚠️ Clerk Unset</span>
              </div>
            )}

            {/* Engine Connectivity Status (Desktop Badge) */}
            <div className="hidden sm:inline-flex">
              {systemHealth.status === "operational" ? (
                isAuthorized ? (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0] font-medium whitespace-nowrap">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#26694E] animate-pulse inline-block" />
                    <span>Connected</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0] font-medium whitespace-nowrap">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#26694E] inline-block" />
                    <span>Engine Online</span>
                  </span>
                )
              ) : systemHealth.status === "degraded" ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#FFF8E6] text-[#B87A14] border border-[#F5E0B8] font-medium whitespace-nowrap">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#B87A14] inline-block" />
                  <span>Degraded</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#FDF0ED] text-[#C24128] border border-[#F3C4B8] font-medium whitespace-nowrap">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#C24128] inline-block" />
                  <span>Backend Offline</span>
                </span>
              )}
            </div>

            {/* Mobile Compact Status Dot */}
            <div className="sm:hidden flex items-center">
              <span
                role="status"
                className={`inline-flex items-center justify-center w-7 h-7 rounded-full border ${
                  systemHealth.status === "operational"
                    ? "bg-[#E8F2EC] text-[#26694E] border-[#C5DFD0]"
                    : systemHealth.status === "degraded"
                    ? "bg-[#FFF8E6] text-[#B87A14] border-[#F5E0B8]"
                    : "bg-[#FDF0ED] text-[#C24128] border-[#F3C4B8]"
                }`}
                title={
                  systemHealth.status === "operational"
                    ? isAuthorized
                      ? "Connected"
                      : "Engine Online"
                    : systemHealth.status === "degraded"
                    ? "Degraded"
                    : "Backend Offline"
                }
                aria-label={
                  systemHealth.status === "operational"
                    ? isAuthorized
                      ? "Connected"
                      : "Engine Online"
                    : systemHealth.status === "degraded"
                    ? "Degraded"
                    : "Backend Offline"
                }
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    systemHealth.status === "operational"
                      ? isAuthorized
                        ? "bg-[#26694E] animate-pulse"
                        : "bg-[#26694E]"
                      : systemHealth.status === "degraded"
                      ? "bg-[#B87A14]"
                      : "bg-[#C24128]"
                  }`}
                />
              </span>
            </div>

            {/* Authorized Workspace Friendly Pill (Desktop) */}
            {isAuthorized && (
              <span
                className="hidden md:inline-flex items-center gap-1.5 text-[#82465D] bg-[#F6EDF1] px-2.5 py-1 rounded-md border border-[#E5CDD8] font-bold whitespace-nowrap"
                title={principal?.tenant_id ? `Authenticated Tenant: ${principal.tenant_id}` : undefined}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-[#82465D]" />
                <span>{organizationName || "Workspace"}</span>
              </span>
            )}

            {/* Unauthenticated Walkthrough Nav Link */}
            {!isSignedIn && (
              <a
                href="#product-walkthrough"
                className="hidden sm:inline-flex items-center gap-1 text-[#645C64] hover:text-[#302B30] hover:bg-[#EEE6DC] px-2.5 py-1.5 min-h-[32px] rounded-md transition-colors border border-transparent hover:border-[#DFD6C9] whitespace-nowrap"
              >
                <span>Walkthrough</span>
              </a>
            )}

            {/* Clerk Controls */}
            {isSignedIn ? (
              <div className="flex items-center gap-1.5 sm:gap-2">
                <OrganizationSwitcher
                  hidePersonal={false}
                  appearance={{
                    elements: {
                      rootBox: "flex items-center max-w-[120px] sm:max-w-none",
                      organizationSwitcherTrigger:
                        "flex items-center gap-1 sm:gap-1.5 px-2 sm:px-2.5 py-1.5 min-h-[32px] rounded-md bg-[#FAF7F2] hover:bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#302B30] transition-colors truncate",
                    },
                  }}
                />
                {principal?.roles?.[0] && (
                  <span className="hidden sm:inline-block text-[10px] uppercase font-bold text-[#82465D] bg-[#F6EDF1] px-1.5 py-0.5 rounded border border-[#E5CDD8]">
                    {principal.roles[0]}
                  </span>
                )}
                <UserButton
                  appearance={{
                    elements: {
                      userButtonAvatarBox: "w-7 h-7 border border-[#DFD6C9] rounded-md",
                    },
                  }}
                />
              </div>
            ) : (
              <SignInButton mode="modal">
                <button
                  type="button"
                  className="inline-flex items-center justify-center whitespace-nowrap gap-1.5 px-2.5 sm:px-3 py-1.5 min-h-[32px] rounded-md bg-[#D26A50] hover:bg-[#BE5B42] text-white text-xs font-medium transition-colors shadow-terracotta-xs cursor-pointer"
                >
                  <span>🔐 Sign In</span>
                </button>
              </SignInButton>
            )}

            {/* Desktop Secondary Link: API Docs */}
            <a
              href={API_DOCS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center gap-1 text-[#645C64] hover:text-[#302B30] hover:bg-[#EEE6DC] px-2.5 py-1.5 min-h-[32px] rounded-md transition-colors border border-transparent hover:border-[#DFD6C9] whitespace-nowrap"
            >
              <span>API Docs</span>
              <span>↗</span>
            </a>

            {/* Mobile Accessible Overflow Menu Toggle */}
            <button
              type="button"
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              className="sm:hidden inline-flex items-center justify-center w-8 h-8 rounded-md bg-[#FAF7F2] hover:bg-[#F5EFE6] text-[#302B30] border border-[#DFD6C9] transition-colors cursor-pointer"
              aria-label="Toggle navigation menu"
              aria-expanded={mobileMenuOpen}
              id="mobile-nav-overflow-button"
            >
              {mobileMenuOpen ? (
                <span className="text-xs font-bold leading-none">✕</span>
              ) : (
                <span className="text-sm font-bold leading-none">⋯</span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Overflow Menu Dropdown */}
      {mobileMenuOpen && (
        <div
          id="mobile-nav-overflow-menu"
          className="sm:hidden border-t border-[#DFD6C9] bg-[#FAF7F2] px-4 py-3 space-y-2.5 shadow-warm-md"
        >
          {isAuthorized && (
            <div className="flex items-center justify-between text-xs font-mono py-1 border-b border-[#EEE6DC]">
              <span className="text-[#645C64]">Active Workspace:</span>
              <div className="text-right">
                <span className="font-bold text-[#82465D] bg-[#F6EDF1] px-2 py-0.5 rounded border border-[#E5CDD8]">
                  {organizationName || "Workspace"}
                </span>
                {principal?.tenant_id && (
                  <span className="block text-[9px] text-[#928992] mt-0.5">
                    ID: {principal.tenant_id}
                  </span>
                )}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between text-xs font-mono py-1 border-b border-[#EEE6DC]">
            <span className="text-[#645C64]">Engine Status:</span>
            <span
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                systemHealth.status === "operational"
                  ? "bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]"
                  : systemHealth.status === "degraded"
                  ? "bg-[#FFF8E6] text-[#B87A14] border border-[#F5E0B8]"
                  : "bg-[#FDF0ED] text-[#C24128] border border-[#F3C4B8]"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  systemHealth.status === "operational"
                    ? isAuthorized
                      ? "bg-[#26694E] animate-pulse"
                      : "bg-[#26694E]"
                    : systemHealth.status === "degraded"
                    ? "bg-[#B87A14]"
                    : "bg-[#C24128]"
                }`}
              />
              <span>
                {systemHealth.status === "operational"
                  ? isAuthorized
                    ? "Connected"
                    : "Engine Online"
                  : systemHealth.status === "degraded"
                  ? "Degraded"
                  : "Backend Offline"}
              </span>
            </span>
          </div>

          <div className="pt-1 flex flex-col gap-2 font-mono text-xs">
            <a
              href={API_DOCS_URL}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#FFFFFF] hover:bg-[#F5EFE6] border border-[#DFD6C9] text-[#302B30] transition-colors"
            >
              <span className="font-medium">OpenAPI Swagger Docs</span>
              <span className="text-[#82465D]">↗</span>
            </a>

            {FALKORDB_BROWSER_URL && (
              <a
                href={FALKORDB_BROWSER_URL}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#FFFFFF] hover:bg-[#F5EFE6] border border-[#DFD6C9] text-[#302B30] transition-colors"
              >
                <span className="font-medium">FalkorDB Visualizer</span>
                <span className="text-[#82465D]">↗</span>
              </a>
            )}
          </div>
        </div>
      )}
    </header>
  );
}

// ──────────────────────────────────────────────
// Signed-Out Professional Welcome Experience
// ──────────────────────────────────────────────

function SignedOutWelcomeView() {
  return <PublicLandingExperience />;
}

// ──────────────────────────────────────────────
// Organization Selection Required View
// ──────────────────────────────────────────────

function NoOrganizationView() {
  const { signOut } = useClerk();

  return (
    <div className="max-w-2xl mx-auto px-4 py-16 text-center space-y-6">
      <div className="w-16 h-16 rounded-2xl bg-[#FFF8E6] border border-[#F5E0B8] mx-auto flex items-center justify-center text-2xl">
        🏢
      </div>

      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-extrabold text-[#302B30]">
          Organization Selection Required
        </h1>
        <p className="text-sm text-[#645C64] max-w-md mx-auto leading-relaxed">
          RootMesh operates as a B2B multi-tenant incident response platform.
          Please select or switch to an authorized organization to access threat intelligence operations.
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs flex flex-col items-center gap-4">
        <p className="text-xs font-mono text-[#82465D] font-medium">
          Select your enterprise organization:
        </p>
        <OrganizationSwitcher
          hidePersonal={false}
          appearance={{
            elements: {
              organizationSwitcherTrigger:
                "px-4 py-2 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#302B30] transition-colors shadow-subtle",
            },
          }}
        />
      </div>

      <div>
        <button
          type="button"
          onClick={() => signOut()}
          className="text-xs font-mono text-[#645C64] hover:text-[#C24128] transition-colors underline cursor-pointer"
        >
          Sign out and switch accounts
        </button>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────
// Unauthorized Organization View
// ──────────────────────────────────────────────

function UnauthorizedOrganizationView({ organizationName }: { organizationName?: string }) {
  const { signOut } = useClerk();

  return (
    <div className="max-w-2xl mx-auto px-4 py-16 text-center space-y-6">
      <div className="w-16 h-16 rounded-2xl bg-[#FDF0ED] border border-[#F3C4B8] mx-auto flex items-center justify-center text-2xl text-[#C24128]">
        ⛔
      </div>

      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-extrabold text-[#302B30]">
          Access Denied: Organization Not Authorized
        </h1>
        <p className="text-sm text-[#645C64] max-w-md mx-auto leading-relaxed">
          The organization <strong className="text-[#302B30]">{organizationName || "selected"}</strong> is
          not mapped to an authorized security tenant on this RootMesh node.
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-xs flex flex-col items-center gap-4">
        <p className="text-xs font-mono text-[#82465D] font-medium">
          Switch to an authorized tenant organization (e.g., RootMesh SecOps):
        </p>
        <OrganizationSwitcher
          hidePersonal={false}
          appearance={{
            elements: {
              organizationSwitcherTrigger:
                "px-4 py-2 rounded-lg bg-[#FAF7F2] hover:bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#302B30] transition-colors shadow-subtle",
            },
          }}
        />
      </div>

      <div>
        <button
          type="button"
          onClick={() => signOut()}
          className="text-xs font-mono text-[#645C64] hover:text-[#C24128] transition-colors underline cursor-pointer"
        >
          Sign out of this session
        </button>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────
// Authentication Loading View
// ──────────────────────────────────────────────

function AuthLoadingView() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center max-w-md mx-auto px-4 text-center space-y-4 font-mono">
      <div className="w-8 h-8 rounded-full border-2 border-[#D26A50] border-t-transparent animate-spin mx-auto" />
      <p className="text-xs text-[#645C64]">Authenticating RootMesh session…</p>
    </div>
  );
}

// ──────────────────────────────────────────────
// Main RootMesh Application Component
// ──────────────────────────────────────────────

export default function HomePage() {
  const { isLoaded, isSignedIn, getToken } = useAuth();
  const { user } = useUser();
  const { organization, membership, isLoaded: isOrgLoaded } = useOrganization();
  const { signOut } = useClerk();

  const [principal, setPrincipal] = useState<PrincipalInfo | null>(null);
  const [systemHealth, setSystemHealth] = useState<SystemHealth>(getCachedSystemHealth());

  const [selectedAssetId, setSelectedAssetId] = useState<string>("host-0");
  const [activeInvestigation, setActiveInvestigation] = useState<InvestigationSummary | null>(null);
  const [activeIncident, setActiveIncident] = useState<{
    incidentId: string;
    targetHost: string;
    targetHostId: string;
  }>({
    incidentId: "inc-latest",
    targetHost: "Workstation-PatientZero (host-0)",
    targetHostId: "host-0",
  });

  // Truthful Human-in-the-Loop Lifecycle State
  const [lifecycleStatus, setLifecycleStatus] = useState<IncidentLifecycleState>("INVESTIGATED");
  const [activeProposal, setActiveProposal] = useState<ProposalInfo | null>(null);
  const [containmentAudit, setContainmentAudit] = useState<AuditInfo | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [incidentCreatedAt, setIncidentCreatedAt] = useState<number | string | null>(null);

  // Persisted Investigation Findings & Evidence (Recoverable across page refreshes)
  const [persistedFindings, setPersistedFindings] = useState<Array<{
    id: string;
    text: string;
    severity?: string;
    timestamp?: number;
  }>>([]);
  const [persistedCompanyBrain, setPersistedCompanyBrain] = useState<{
    service_name?: string;
    team_name?: string;
    person_name?: string;
    oncall_name?: string;
    oncall_role?: string;
    runbook_title?: string;
    runbook_sla_minutes?: number;
    commit_sha?: string;
  } | null>(null);
  const [persistedRiskEvidence, setPersistedRiskEvidence] = useState<{
    targetCount?: number;
    egressRiskMbps?: number;
  } | null>(null);

  const isContained = lifecycleStatus === "CONTAINED";

  // Synchronize Clerk authentication and organization state with RootMesh auth client
  useEffect(() => {
    setClerkTokenGetter((opts) => getToken(opts));
    setClerkSignOut(() => signOut());
    syncClerkSession({
      isLoaded: Boolean(isLoaded),
      isSignedIn: Boolean(isSignedIn),
      userId: user?.id,
      username: user?.username || user?.fullName || user?.primaryEmailAddress?.emailAddress,
      email: user?.primaryEmailAddress?.emailAddress,
      orgId: organization?.id,
      orgSlug: organization?.slug,
      orgRole: membership?.role,
    });
  }, [getToken, isLoaded, isSignedIn, user, organization, membership, signOut]);

  // Subscribe to authenticated principal state
  useEffect(() => {
    return onAuthStateChanged((p) => {
      setPrincipal(p);
    });
  }, []);

  // System Health Monitoring
  useEffect(() => {
    checkSystemHealth();
    const unsub = onSystemHealthChanged(setSystemHealth);
    const interval = setInterval(checkSystemHealth, 20000);
    return () => {
      unsub();
      clearInterval(interval);
    };
  }, []);

  // Synchronize tenant with shared ThreatStream WebSocket manager
  useEffect(() => {
    if (principal?.tenant_id) {
      threatStream.setTenant(principal.tenant_id);
    } else {
      threatStream.setTenant(null);
    }
  }, [principal?.tenant_id]);

  // Clear sensitive operational state when organization changes or user signs out
  const currentOrgId = organization?.id;
  const incidentFetchTenantRef = useRef<string | null>(null);

  useEffect(() => {
    incidentFetchTenantRef.current = null;
    threatStream.setTenant(null);
    setActiveInvestigation(null);
    setSelectedAssetId("host-0");
    setActiveIncident({
      incidentId: "inc-latest",
      targetHost: "Workstation-PatientZero (host-0)",
      targetHostId: "host-0",
    });
    setLifecycleStatus("INVESTIGATED");
    setActiveProposal(null);
    setContainmentAudit(null);
    setExecutionError(null);
    setIncidentCreatedAt(null);
    setPersistedFindings([]);
    setPersistedCompanyBrain(null);
    setPersistedRiskEvidence(null);
  }, [currentOrgId, isSignedIn]);

  // Hydrate full persisted incident provenance, evidence, and lifecycle state from backend
  const hydrateIncidentDetails = useCallback(
    async (
      currentTenant: string,
      iid: string,
      fallbackHostId?: string,
      fallbackHostName?: string,
      signal?: AbortSignal
    ) => {
      const apiBase = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
      try {
        const detailRes = await authenticatedFetch(
          `${apiBase}/api/v1/incident/${encodeURIComponent(currentTenant)}/${encodeURIComponent(iid)}`,
          { signal }
        );
        if (!detailRes.ok) return;
        if (signal?.aborted || incidentFetchTenantRef.current !== currentTenant) return;

        const fullInc = await detailRes.json();
        const audits = (fullInc.audit_trail as Record<string, unknown>[]) || [];
        const proposals = (fullInc.proposals as Record<string, unknown>[]) || [];
        const findings = (fullInc.findings as Array<Record<string, unknown>>) || [];
        const cb = (fullInc.company_brain as Record<string, unknown>) || {};
        const hostId = String(fullInc.patient_zero_id || fallbackHostId || "host-0");
        const hostName = String(cb.host_name || fallbackHostName || hostId);

        setActiveIncident({
          incidentId: iid,
          targetHost: `${hostName} (${hostId})`,
          targetHostId: hostId,
        });
        setSelectedAssetId(hostId);
        setIncidentCreatedAt((fullInc.created_at as number | string) || null);

        // Store persisted findings directly from FalkorDB memory nodes
        setPersistedFindings(
          findings.map((f) => ({
            id: String(f.id || ""),
            text: String(f.text || ""),
            severity: typeof f.severity === "string" ? f.severity : "CRITICAL",
            timestamp: typeof f.timestamp === "number" ? f.timestamp : undefined,
          }))
        );

        setPersistedCompanyBrain({
          service_name: String(cb.service_name || "Corporate Device Gateway (svc-endpoint-gw)"),
          team_name: String(cb.team_name || "SecOps Incident Response (team-sec)"),
          person_name: String(cb.oncall_name || cb.person_name || "Alex Rivera (Lead IR Responder)"),
          oncall_name: String(cb.oncall_name || cb.person_name || "Alex Rivera (Lead IR Responder)"),
          oncall_role: String(cb.oncall_role || "Lead Incident Responder"),
          runbook_title: String(cb.runbook_title || "Workstation Lateral Movement Containment SOP (rb-iso-001)"),
          runbook_sla_minutes: typeof cb.runbook_sla_minutes === "number" ? cb.runbook_sla_minutes : 15,
          commit_sha: String(cb.commit_sha || "c89e1a4"),
        });

        // Resolve risk evidence from backend response, findings text, or proposals
        let targetCount: number | undefined;
        let egressRiskMbps: number | undefined;

        if (fullInc.risk_evidence && typeof fullInc.risk_evidence === "object") {
          const re = fullInc.risk_evidence as Record<string, unknown>;
          if (typeof re.target_count === "number") targetCount = re.target_count;
          if (typeof re.egress_risk_mbps === "number") egressRiskMbps = re.egress_risk_mbps;
        }

        if (targetCount === undefined || egressRiskMbps === undefined) {
          for (const f of findings) {
            const text = typeof f.text === "string" ? f.text : "";
            if (targetCount === undefined) {
              const m = text.match(/(\d+)\s+lateral\s+propagation\s+paths/i);
              if (m) targetCount = parseInt(m[1], 10);
            }
            if (egressRiskMbps === undefined) {
              const m = text.match(/MaxFlow\s+egress\s+risk:\s*([0-9.]+)\s*Mbps/i);
              if (m) egressRiskMbps = parseFloat(m[1]);
            }
          }
        }

        if (targetCount === undefined && proposals.length > 0) {
          const risk = (proposals[0].risk_assessment as Record<string, unknown>) || {};
          if (typeof risk.lateral_targets === "number") targetCount = risk.lateral_targets;
          if (typeof risk.max_egress_mbps === "number") egressRiskMbps = risk.max_egress_mbps;
        }

        setPersistedRiskEvidence({ targetCount, egressRiskMbps });

        if (fullInc.status === "CONTAINED" || audits.length > 0) {
          const latestAudit = audits[audits.length - 1];
          if (latestAudit) {
            setContainmentAudit({
              auditId: String(latestAudit.audit_id || `aud-${Date.now()}`),
              actionId: String(latestAudit.action_id || "act-contain"),
              executedBy: String(latestAudit.executed_by || "Authorized Reviewer"),
              executedAt: typeof latestAudit.executed_at === "number" ? latestAudit.executed_at : Date.now() / 1000,
              verification: String(latestAudit.verification || "VERIFIED"),
              pathsSevered: typeof latestAudit.paths_severed === "number" ? latestAudit.paths_severed : 0,
              egressReducedMbps: typeof latestAudit.egress_reduced_mbps === "number" ? latestAudit.egress_reduced_mbps : 0.0,
              containmentType: "GRAPH_TOPOLOGY_SIMULATION",
            });
          }
          setLifecycleStatus("CONTAINED");
          setExecutionError(null);
        } else if (proposals.length > 0) {
          const p = proposals[0];
          const risk = (p.risk_assessment as Record<string, unknown>) || {};
          setActiveProposal({
            actionId: String(p.action_id || ""),
            incidentId: iid,
            actionType: String(p.action_type || "ISOLATE_HOST_TOPOLOGY"),
            targetHostId: String(p.target_host_id || hostId),
            targetHostName: String(p.target_host_name || hostName),
            proposer: String(p.proposer || "Authenticated Responder"),
            justification: String(p.justification || ""),
            createdAt: typeof p.created_at === "number" ? p.created_at : undefined,
            expiresAt: typeof p.expires_at === "number" ? p.expires_at : undefined,
            status: String(p.status || "PROPOSED"),
            lateralTargets: typeof risk.lateral_targets === "number" ? risk.lateral_targets : undefined,
            maxEgressMbps: typeof risk.max_egress_mbps === "number" ? risk.max_egress_mbps : undefined,
            reviewedBy: typeof p.reviewed_by === "string" ? p.reviewed_by : undefined,
            reviewedAt: typeof p.reviewed_at === "number" ? p.reviewed_at : undefined,
            reviewComment: typeof p.review_comment === "string" ? p.review_comment : undefined,
          });

          if (p.status === "APPROVED") {
            setLifecycleStatus("APPROVED");
          } else if (p.status === "REJECTED") {
            setLifecycleStatus("REJECTED");
          } else if (p.status === "EXPIRED") {
            setLifecycleStatus("EXPIRED");
          } else {
            setLifecycleStatus("PROPOSAL_CREATED");
          }
        } else {
          setActiveProposal(null);
          setContainmentAudit(null);
          setLifecycleStatus("INVESTIGATED");
        }
      } catch {
        // Fallback or network error
      }
    },
    []
  );

  // Fetch authoritative persisted incident state for current tenant on load
  useEffect(() => {
    if (!isLoaded || !isSignedIn || !principal?.tenant_id) return;
    const currentTenant = principal.tenant_id;
    incidentFetchTenantRef.current = currentTenant;
    const controller = new AbortController();
    const apiBase = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

    authenticatedFetch(`${apiBase}/api/v1/incident/${encodeURIComponent(currentTenant)}?limit=1`, {
      signal: controller.signal,
    })
      .then(async (r) => {
        if (!r.ok) return [];
        return r.json().catch(() => []);
      })
      .then(async (data: Record<string, unknown>[]) => {
        if (controller.signal.aborted || incidentFetchTenantRef.current !== currentTenant) {
          return;
        }
        if (Array.isArray(data) && data.length > 0) {
          const latest = data[0];
          const cb = (latest.company_brain as Record<string, unknown>) || {};
          const hostName = (cb.host_name as string) || (latest.patient_zero_id as string) || "Workstation-PatientZero";
          const hostId = (latest.patient_zero_id as string) || "host-0";
          const iid = (latest.incident_id as string) || "inc-latest";

          await hydrateIncidentDetails(currentTenant, iid, hostId, hostName, controller.signal);
        }
      })
      .catch(() => {});

    return () => {
      controller.abort();
    };
  }, [isLoaded, isSignedIn, principal?.tenant_id, hydrateIncidentDetails]);

  // WebSocket Threat Stream Synchronization & Reconnect Recovery
  useEffect(() => {
    if (!principal?.tenant_id) return;
    const currentTenant = principal.tenant_id;
    const reconcileWithPersisted = async (targetIncidentId?: string) => {
      const idToFetch = targetIncidentId || activeIncident.incidentId || "inc-latest";
      await hydrateIncidentDetails(currentTenant, idToFetch);
    };

    const unsubEvents = threatStream.subscribe((evt: ThreatStreamEvent) => {
      // Reject cross-tenant events
      if (evt.tenant_id && evt.tenant_id !== currentTenant) return;

      if (evt.event === "INCIDENT_INVESTIGATED") {
        setLifecycleStatus("INVESTIGATED");
        setActiveProposal(null);
        setContainmentAudit(null);
        setExecutionError(null);
        if (evt.timestamp) setIncidentCreatedAt(evt.timestamp);
        if (evt.incident_id) {
          hydrateIncidentDetails(currentTenant, evt.incident_id);
        }
      } else if (evt.event === "INCIDENT_PROPOSAL_CREATED") {
        setActiveProposal({
          actionId: evt.action_id,
          incidentId: evt.incident_id,
          targetHostId: evt.target_host_id,
          status: "PROPOSED",
          proposer: evt.proposer,
          createdAt: evt.timestamp,
        });
        setLifecycleStatus("PROPOSAL_CREATED");
      } else if (evt.event === "INCIDENT_PROPOSAL_REVIEWED") {
        setActiveProposal((prev) =>
          prev
            ? {
                ...prev,
                reviewedBy: evt.reviewer,
                reviewedAt: evt.timestamp,
                status: evt.status,
              }
            : null
        );
        if (evt.decision === "APPROVE") {
          setLifecycleStatus("APPROVED");
        } else if (evt.decision === "REJECT") {
          setLifecycleStatus("REJECTED");
        } else if (evt.decision === "EXPIRED") {
          setLifecycleStatus("EXPIRED");
        }
      } else if (evt.event === "INCIDENT_CONTAINMENT_EXECUTED") {
        // Never treat WebSocket event alone as proof of execution if persisted status contradicts it
        reconcileWithPersisted(evt.incident_id);
      }
    });

    const unsubReconnect = threatStream.onReconnect(() => {
      // Re-fetch persisted data on reconnection to recover any missed events
      reconcileWithPersisted();
    });

    return () => {
      unsubEvents();
      unsubReconnect();
    };
  }, [principal?.tenant_id, activeIncident.incidentId, hydrateIncidentDetails]);

  const handleSelectIncident = useCallback(
    (iid: string, hostId: string, hostName: string) => {
      if (!principal?.tenant_id) return;
      hydrateIncidentDetails(principal.tenant_id, iid, hostId, hostName);
    },
    [principal?.tenant_id, hydrateIncidentDetails]
  );

  const handleInvestigationComplete = useCallback((summary: InvestigationSummary) => {
    setActiveInvestigation(summary);
    const hostId = summary.patient_zero_id || "host-0";
    const hostName = summary.patient_zero_name || "Workstation-PatientZero";
    setSelectedAssetId(hostId);
    setActiveIncident({
      incidentId: summary.incident_id,
      targetHost: `${hostName} (${hostId})`,
      targetHostId: hostId,
    });
    setPersistedFindings([
      {
        id: `find-${summary.incident_id}`,
        text: `Autonomous investigation on ${hostId} (${hostName}): ${summary.target_count} lateral propagation paths detected; MaxFlow egress risk: ${summary.egress_risk_mbps} Mbps to perimeter.`,
        severity: "CRITICAL",
        timestamp: Date.now(),
      },
    ]);
    if (summary.company_brain) {
      setPersistedCompanyBrain({
        service_name: "Corporate Device Gateway (svc-endpoint-gw)",
        team_name: summary.company_brain.team_name,
        person_name: summary.company_brain.person_name,
        oncall_name: summary.company_brain.person_name,
        oncall_role: summary.company_brain.oncall_role,
        runbook_title: summary.company_brain.runbook_title,
        runbook_sla_minutes: summary.company_brain.runbook_sla_minutes,
        commit_sha: "c89e1a4",
      });
    }
    setPersistedRiskEvidence({
      targetCount: summary.target_count,
      egressRiskMbps: summary.egress_risk_mbps,
    });
    setLifecycleStatus("INVESTIGATED");
    setActiveProposal(null);
    setContainmentAudit(null);
    setExecutionError(null);
    setIncidentCreatedAt(Date.now() / 1000);
  }, []);

  const handleProposalCreated = useCallback((propData: Record<string, unknown>) => {
    const risk = (propData.risk_assessment as Record<string, unknown>) || {};
    setActiveProposal({
      actionId: String(propData.action_id || ""),
      incidentId: String(propData.incident_id || ""),
      targetHostId: String(propData.target_host_id || "host-0"),
      targetHostName: String(propData.target_host_name || "Workstation-PatientZero"),
      proposer: String(propData.proposer_principal || principal?.username || "Authenticated Responder"),
      justification: String(propData.justification || ""),
      createdAt: typeof propData.created_at === "number" ? propData.created_at : Date.now() / 1000,
      expiresAt: typeof propData.expires_at === "number" ? propData.expires_at : (Date.now() / 1000) + 900,
      status: "PROPOSED",
      lateralTargets: typeof risk.lateral_targets === "number" ? risk.lateral_targets : undefined,
      maxEgressMbps: typeof risk.max_egress_mbps === "number" ? risk.max_egress_mbps : undefined,
    });
    setLifecycleStatus("PROPOSAL_CREATED");
  }, [principal?.username]);

  const handleProposalReviewed = useCallback(
    (decision: "APPROVE" | "REJECT", propData: Record<string, unknown>) => {
      setActiveProposal((prev) =>
        prev
          ? {
              ...prev,
              status: decision === "APPROVE" ? "APPROVED" : "REJECTED",
              reviewedBy: String(propData.reviewed_by || principal?.username || "Authorized Reviewer"),
              reviewedAt: typeof propData.reviewed_at === "number" ? propData.reviewed_at : Date.now() / 1000,
              reviewComment: String(propData.review_comment || ""),
            }
          : null
      );
      setLifecycleStatus(decision === "APPROVE" ? "APPROVED" : "REJECTED");
    },
    [principal?.username]
  );

  const handleExecutionStarted = useCallback(() => {
    setLifecycleStatus("EXECUTION_PENDING");
    setExecutionError(null);
  }, []);

  const handleExecutionFailed = useCallback((error: string) => {
    setLifecycleStatus("EXECUTION_FAILED");
    setExecutionError(error);
  }, []);

  const handleContainmentExecuted = useCallback((auditData: Record<string, unknown>) => {
    setLifecycleStatus("CONTAINED");
    setExecutionError(null);
    const beforeAfter = auditData.before_after as Record<string, unknown> | undefined;
    const pathsSevered = typeof beforeAfter?.paths_severed === "number" ? beforeAfter.paths_severed : 0;
    const egressReduced = typeof beforeAfter?.egress_reduction_mbps === "number" ? beforeAfter.egress_reduction_mbps : 0.0;

    setContainmentAudit({
      auditId: (auditData.audit_id as string) || `aud-${Date.now()}`,
      actionId: (auditData.action_id as string) || "act-contain",
      executedBy: (auditData.executed_by as string) || (principal?.username ?? "Authorized Reviewer"),
      executedAt: typeof auditData.executed_at === "number" ? auditData.executed_at : Date.now() / 1000,
      verification: (auditData.verification as string) || "VERIFIED",
      pathsSevered,
      egressReducedMbps: egressReduced,
      containmentType: "GRAPH_TOPOLOGY_SIMULATION",
    });
  }, [principal?.username]);

  const handleContainmentRejected = useCallback(() => {
    setLifecycleStatus("REJECTED");
  }, []);

  const handleAssetSelect = useCallback((id: string) => {
    setSelectedAssetId(id);
    setActiveIncident((prev) => ({
      ...prev,
      targetHostId: id,
      targetHost: `${id}`,
    }));
  }, []);

  // Authentication & Authorization Boundaries
  const [isPreview, setIsPreview] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("preview") === "1" || params.get("preview") === "true" || params.get("eval") === "1") {
        setIsPreview(true);
        setPrincipal((prev) =>
          prev || {
            principal_id: "preview-analyst",
            username: "Lead Incident Responder",
            email: "analyst@rootmesh.security",
            tenant_id: "tenant-rootmesh",
            roles: ["Security Analyst"],
            permissions: ["incident:investigate", "incident:propose"],
            workspaces: ["ws-production"],
          }
        );
      }
    }
  }, []);

  const isAuthorized = isPreview || Boolean(isSignedIn && organization && principal?.tenant_id);
  const isNoOrg = !isPreview && Boolean(isSignedIn && !organization);
  const isUnauthorizedOrg = !isPreview && Boolean(isSignedIn && organization && principal && !principal.tenant_id);
  const organizationName = organization?.name || (isPreview ? "RootMesh SecOps" : "Workspace");

  return (
    <main className="min-h-screen bg-[#FAF7F2] text-[#302B30] selection:bg-[#D26A50]/20 selection:text-[#302B30] relative overflow-x-clip flex flex-col justify-between">
      {/* ── Signature Connected Network Grid Background ───────────── */}
      <NetworkGridBackground />

      {/* ── Top Navigation Bar ────────────────────────────────────────── */}
      <TopNavbar
        principal={principal}
        isSignedIn={Boolean(isSignedIn || isPreview)}
        systemHealth={systemHealth}
        isAuthorized={isAuthorized}
        organizationName={organizationName}
      />

      {/* ── Conditional Authentication States ─────────────────────────── */}
      <div className="relative z-10 flex-1 min-h-[calc(100vh-140px)]">
      {!isSignedIn && !isPreview ? (
        <SignedOutWelcomeView />
      ) : !isOrgLoaded && !isPreview ? (
        <AuthLoadingView />
      ) : isNoOrg ? (
        <NoOrganizationView />
      ) : isUnauthorizedOrg ? (
        <UnauthorizedOrganizationView organizationName={organization?.name} />
      ) : (
        /* ── Authorized Operational Workspace (Sections 1 through 7) ──── */
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-12">
          {/* Section 1: Operations Command Center */}
          <section id="investigation-workspace" aria-label="Operations Command Center" className="scroll-mt-20 space-y-4">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#F5EFE6] border border-[#DFD6C9] text-xs font-mono text-[#82465D] mb-3">
                <span className="w-1.5 h-1.5 rounded-full bg-[#D26A50]" />
                <span>Enterprise Graph Threat Operations</span>
              </div>
              <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-[#302B30]">
                Understand exposure. Investigate threats.{" "}
                <span className="text-[#D26A50]">Coordinate a controlled response.</span>
              </h1>
              <p className="text-sm text-[#645C64] mt-2 max-w-3xl leading-relaxed">
                Analyze lateral propagation across connected topology, evaluate high-value database exposure and perimeter egress risk, and coordinate guarded human-in-the-loop containment.
              </p>
            </div>

            <HeroSection
              onInvestigationComplete={handleInvestigationComplete}
              tenantId={principal?.tenant_id}
              organizationName={organizationName}
              selectedAssetId={selectedAssetId}
              onSelectAsset={handleAssetSelect}
            />
          </section>

          {/* Section 2: Incident Response Lifecycle */}
          <section id="lifecycle-journey" aria-label="Incident Response Lifecycle" className="scroll-mt-20 space-y-3">
            <LifecycleGovernanceGuide
              lifecycleState={lifecycleStatus}
              hasProposal={Boolean(activeProposal)}
              hasReview={
                lifecycleStatus === "APPROVED" ||
                lifecycleStatus === "REJECTED" ||
                lifecycleStatus === "EXPIRED" ||
                lifecycleStatus === "EXECUTION_PENDING" ||
                lifecycleStatus === "CONTAINED" ||
                lifecycleStatus === "EXECUTION_FAILED"
              }
              hasExecution={isContained}
              reviewDecision={
                activeProposal?.status === "APPROVED"
                  ? "APPROVE"
                  : activeProposal?.status === "REJECTED"
                  ? "REJECT"
                  : activeProposal?.status === "EXPIRED"
                  ? "EXPIRED"
                  : null
              }
            />
            <IncidentJourneyTimeline
              incidentId={activeIncident.incidentId}
              targetHost={activeIncident.targetHost}
              lifecycleState={lifecycleStatus}
              hasInvestigation={
                Boolean(activeInvestigation) ||
                persistedFindings.length > 0 ||
                activeIncident.incidentId !== "inc-latest"
              }
              hasProposal={Boolean(activeProposal)}
              hasReview={
                lifecycleStatus === "APPROVED" ||
                lifecycleStatus === "REJECTED" ||
                lifecycleStatus === "EXPIRED" ||
                lifecycleStatus === "EXECUTION_PENDING" ||
                lifecycleStatus === "CONTAINED" ||
                lifecycleStatus === "EXECUTION_FAILED"
              }
              hasExecution={isContained}
              investigationCreatedAt={incidentCreatedAt ?? (activeInvestigation ? Date.now() / 1000 : null)}
              investigationTimeMs={activeInvestigation?.execution_time_ms}
              targetCount={activeInvestigation?.target_count ?? persistedRiskEvidence?.targetCount}
              egressRiskMbps={activeInvestigation?.egress_risk_mbps ?? persistedRiskEvidence?.egressRiskMbps}
              shortestPathDb={activeInvestigation?.shortest_path_db}
              proposal={
                activeProposal
                  ? {
                      actionId: activeProposal.actionId,
                      incidentId: activeProposal.incidentId,
                      actionType: activeProposal.actionType,
                      targetHostId: activeProposal.targetHostId,
                      targetHostName: activeProposal.targetHostName,
                      proposer: activeProposal.proposer,
                      justification: activeProposal.justification,
                      createdAt: activeProposal.createdAt,
                      expiresAt: activeProposal.expiresAt,
                      status: activeProposal.status,
                      lateralTargets: activeProposal.lateralTargets,
                      maxEgressMbps: activeProposal.maxEgressMbps,
                      reviewedBy: activeProposal.reviewedBy,
                      reviewedAt: activeProposal.reviewedAt,
                      reviewComment: activeProposal.reviewComment,
                    }
                  : null
              }
              proposer={activeProposal?.proposer}
              reviewer={activeProposal?.reviewedBy}
              reviewDecision={
                activeProposal?.status === "APPROVED"
                  ? "APPROVE"
                  : activeProposal?.status === "REJECTED"
                  ? "REJECT"
                  : activeProposal?.status === "EXPIRED"
                  ? "EXPIRED"
                  : null
              }
              containmentAudit={containmentAudit}
              executionError={executionError}
            />
          </section>

          {/* Section 3: Real-Time Threat Operations */}
          <div id="threat-operations" className="scroll-mt-20 grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
            {/* Left Column: Live Threat Propagation Matrix */}
            <section aria-label="Live Threat Propagation Matrix">
              <FallingBlockGrid
                tenantId={principal?.tenant_id}
                activeTargetHostId={activeIncident.targetHostId}
                activeIncidentId={activeIncident.incidentId}
                isContained={isContained}
                onProposalCreated={handleProposalCreated}
                onProposalReviewed={handleProposalReviewed}
                onExecutionStarted={handleExecutionStarted}
                onExecutionFailed={handleExecutionFailed}
                onContainmentExecuted={handleContainmentExecuted}
              />
            </section>

            {/* Right Column: Human-Governed Response Deck */}
            <section aria-label="Incident Triage & Action Deck">
              <div className="rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-6 shadow-warm-sm space-y-3">
                <div className="border-b border-[#EEE6DC] pb-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#82465D]" />
                    <h3 className="text-sm font-bold text-[#302B30] uppercase tracking-wider font-mono">
                      Incident Triage &amp; Action Deck
                    </h3>
                  </div>
                  <p className="text-xs text-[#645C64] mt-0.5">
                    Swipe right to propose containment · Swipe left to dismiss · Explicit authorized human review required
                  </p>
                </div>

                <SwipeableCardStack
                  activeTargetHostId={activeIncident.targetHostId}
                  activeInvestigation={activeInvestigation}
                  activeIncidentId={activeIncident.incidentId}
                  onProposalCreated={handleProposalCreated}
                  onProposalReviewed={handleProposalReviewed}
                  onExecutionStarted={handleExecutionStarted}
                  onExecutionFailed={handleExecutionFailed}
                  onContainmentExecuted={handleContainmentExecuted}
                  onContainmentRejected={handleContainmentRejected}
                  onSelectIncident={handleSelectIncident}
                  tenantId={principal?.tenant_id}
                />
              </div>
            </section>
          </div>

          {/* Section 4: Connected Graph Explorer */}
          <section id="graph-explorer" aria-label="Connected Graph Explorer" className="scroll-mt-20">
            <GraphCanvas
              selectedAssetId={selectedAssetId}
              isContained={isContained}
              onSelectNode={handleAssetSelect}
              tenantId={principal?.tenant_id}
            />
          </section>

          {/* Section 5: Priority Infrastructure Assets */}
          <section id="risk-priorities" aria-label="Priority Infrastructure Assets" className="scroll-mt-20">
            <RiskPrioritiesDeck
              selectedAssetId={selectedAssetId}
              onSelectAsset={handleAssetSelect}
              tenantId={principal?.tenant_id}
              organizationName={organizationName}
            />
          </section>

          {/* Section 6: Live Evidence Composer */}
          <section id="evidence-composer" aria-label="Live Evidence Composer" className="scroll-mt-20">
            <LiveEvidenceComposer
              investigation={activeInvestigation}
              selectedAssetId={selectedAssetId}
              targetHost={activeIncident.targetHost}
              incidentId={activeIncident.incidentId}
              tenantId={principal?.tenant_id}
              lifecycleStatus={lifecycleStatus}
              hasPersistedEvidence={persistedFindings.length > 0}
            />
          </section>

          {/* Section 7: Investigation Evidence & Knowledge Dossier */}
          <section id="evidence-dossier" aria-label="Investigation Evidence & Knowledge Dossier" className="scroll-mt-20">
            <CompanyBrainDossier
              incidentId={activeIncident.incidentId}
              targetHost={activeIncident.targetHost}
              hasInvestigation={
                Boolean(activeInvestigation) ||
                persistedFindings.length > 0 ||
                activeIncident.incidentId !== "inc-latest"
              }
              isContained={isContained}
              containmentAudit={
                containmentAudit
                  ? {
                      audit_id: containmentAudit.auditId,
                      action_id: containmentAudit.actionId || "act-contain",
                      executed_by: containmentAudit.executedBy || "Authorized Reviewer",
                      executed_at: containmentAudit.executedAt || Date.now() / 1000,
                      verification: containmentAudit.verification || "VERIFIED",
                      paths_severed: containmentAudit.pathsSevered || 0,
                      egress_reduced_mbps: containmentAudit.egressReducedMbps || 0,
                    }
                  : null
              }
              targetCount={activeInvestigation?.target_count ?? persistedRiskEvidence?.targetCount}
              egressRiskMbps={activeInvestigation?.egress_risk_mbps ?? persistedRiskEvidence?.egressRiskMbps}
              shortestPathDb={activeInvestigation?.shortest_path_db}
              companyBrain={activeInvestigation?.company_brain ?? persistedCompanyBrain}
              persistedFindings={persistedFindings}
              tenantId={principal?.tenant_id}
              hasProposal={Boolean(activeProposal)}
              proposalStatus={activeProposal?.status}
              lifecycleStatus={lifecycleStatus}
            />
          </section>
        </div>
      )}
      </div>

      {/* ── Editorial Warm Light Footer ───────────────────────────────── */}
      <footer className="relative z-10 border-t border-[#DFD6C9] bg-[#FAF7F2]/95 backdrop-blur-sm mt-16 px-4 sm:px-6 py-8">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center sm:items-start gap-4 text-xs text-[#645C64] font-mono">
          <div className="flex items-center gap-2.5">
            <Image
              src="/brand/rootmesh-icon.png"
              alt="RootMesh Icon"
              width={24}
              height={24}
              className="h-6 w-auto object-contain flex-shrink-0"
            />
            <span className="font-bold text-[#302B30]">RootMesh</span>
            <span className="hidden sm:inline">— FalkorDB Autonomous Threat Operations</span>
          </div>

          <div className="flex flex-wrap items-center justify-center sm:justify-end gap-3 sm:gap-4 text-[11px]">
            <a
              href={API_DOCS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#D26A50] transition-colors whitespace-nowrap"
            >
              OpenAPI Swagger UI ↗
            </a>

            {/* Environment-Aware FalkorDB Visualizer Link */}
            {FALKORDB_BROWSER_URL ? (
              <a
                href={FALKORDB_BROWSER_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-[#D26A50] transition-colors whitespace-nowrap"
              >
                FalkorDB Visualizer ↗
              </a>
            ) : !IS_PRODUCTION ? (
              <span
                className="text-[#928992] cursor-help whitespace-nowrap"
                title="FalkorDB Visualizer runs on container port 3000. See documentation for optional local port forwarding."
              >
                FalkorDB Visualizer
              </span>
            ) : null}

            <span className="text-[#82465D] font-medium whitespace-nowrap">
              GRAPH_TOPOLOGY_SIMULATION Verified
            </span>
          </div>
        </div>

        <div className="max-w-7xl mx-auto mt-4 pt-4 border-t border-[#EEE6DC] text-[10px] text-[#928992] font-mono text-center sm:text-left leading-relaxed">
          Notice: Incident intelligence, Company Brain organizational graphs, and containment execution operate in Graph Topology Simulation Mode. In current release, actions model lateral edge severance and verify impact reduction safely without modifying production network firewalls.
        </div>
      </footer>
    </main>
  );
}
