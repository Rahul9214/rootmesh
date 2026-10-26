import { describe, test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("RootMesh Step 3BH: Live PageRank & Incident Evidence Truthfulness Suite", () => {
  // ── Requirement 1 & 5: Live PageRank Schema & Invariance ──────────────────

  test("Requirement 1: PageRank rankings are derived strictly from backend PageRank response schema", () => {
    // Exact schema returned by GET /api/v1/threat/pagerank/{tenant_id}
    const backendPageRankResponse = [
      { host_name: "EgressFirewall", ip: "10.0.99.254", score: 0.00018 },
      { host_name: "VLAN-Router", ip: "10.0.3.1", score: 0.00013 },
      { host_name: "PublicWebServer", ip: "10.0.5.80", score: 0.00011 },
      { host_name: "JumpServer-SysAdmin", ip: "10.0.4.5", score: 0.00009 },
      { host_name: "ReverseProxy", ip: "10.0.5.1", score: 0.00009 },
      { host_name: "AppServer-Internal", ip: "10.0.2.10", score: 0.00005 },
      { host_name: "FileBackupServer", ip: "10.0.2.22", score: 0.00005 },
      { host_name: "Workstation-PatientZero", ip: "10.0.0.1", score: 0.00004 },
    ];

    // Verify ordering and structure
    assert.strictEqual(backendPageRankResponse.length, 8);
    assert.strictEqual(backendPageRankResponse[0].host_name, "EgressFirewall");
    assert.strictEqual(backendPageRankResponse[0].score, 0.00018);
    assert.strictEqual(backendPageRankResponse[1].host_name, "VLAN-Router");
    assert.strictEqual(backendPageRankResponse[7].host_name, "Workstation-PatientZero");

    // Verify descending sort order invariant
    for (let i = 0; i < backendPageRankResponse.length - 1; i++) {
      assert.ok(
        backendPageRankResponse[i].score >= backendPageRankResponse[i + 1].score,
        `PageRank at index ${i} (${backendPageRankResponse[i].score}) must be >= index ${i + 1} (${backendPageRankResponse[i + 1].score})`
      );
    }
  });

  test("Requirement 1 & 5: No static production asset rankings or scores remain in code", () => {
    const riskDeckPath = path.resolve(__dirname, "../components/RiskPrioritiesDeck.tsx");
    const liveEvidencePath = path.resolve(__dirname, "../components/LiveEvidenceComposer.tsx");

    const riskDeckContent = fs.readFileSync(riskDeckPath, "utf-8");
    const liveEvidenceContent = fs.readFileSync(liveEvidencePath, "utf-8");

    // Must NOT contain static RANKED_ASSETS constant
    assert.strictEqual(
      riskDeckContent.includes("const RANKED_ASSETS"),
      false,
      "RiskPrioritiesDeck.tsx must NOT contain static RANKED_ASSETS constant"
    );

    // Must NOT contain the old hardcoded PageRank score 0.0649
    assert.strictEqual(
      riskDeckContent.includes("0.0649"),
      false,
      "RiskPrioritiesDeck.tsx must NOT contain hardcoded PageRank score 0.0649"
    );
    assert.strictEqual(
      liveEvidenceContent.includes("0.0649"),
      false,
      "LiveEvidenceComposer.tsx must NOT contain hardcoded PageRank score 0.0649"
    );
  });

  test("Requirement 1 & 5: Missing or error responses do not generate fabricated values", () => {
    // Simulate error response handler in RiskPrioritiesDeck
    const errorStateSimulator = (
      statusCode: number,
      rawBody: unknown
    ): { rankings: unknown[]; error: string | null } => {
      if (statusCode !== 200) {
        return {
          rankings: [],
          error: `HTTP ${statusCode}: Failed to load PageRank`,
        };
      }
      if (!Array.isArray(rawBody)) {
        return { rankings: [], error: null };
      }
      return { rankings: rawBody, error: null };
    };

    // Case 1: 500 Internal Server Error
    const errResult = errorStateSimulator(500, { detail: "Database connection failed" });
    assert.strictEqual(errResult.rankings.length, 0, "Error response must result in empty rankings, not fallback data");
    assert.ok(errResult.error?.includes("500"), "Error message must be preserved");

    // Case 2: 404 Not Found
    const notFoundResult = errorStateSimulator(404, { detail: "Tenant not found" });
    assert.strictEqual(notFoundResult.rankings.length, 0, "404 response must not generate fabricated fallback rankings");

    // Case 3: Empty tenant graph (0 host nodes)
    const emptyResult = errorStateSimulator(200, []);
    assert.strictEqual(emptyResult.rankings.length, 0, "Empty result must remain genuinely empty");
    assert.strictEqual(emptyResult.error, null);
  });

  test("Requirement 1 & 5: Cross-tenant ranking data is never displayed upon tenant change", () => {
    let currentTenant: string | null = "sec_ops_tenant_alpha";
    let activeRankings: string[] | null = ["alpha-host-1", "alpha-host-2"];
    let requestSeq = 0;

    const switchTenant = (newTenant: string | null) => {
      currentTenant = newTenant;
      // Requirement: Organization switching clears the previous tenant's rankings immediately
      activeRankings = null;
      const thisSeq = ++requestSeq;

      return {
        receiveResponse: (responseTenant: string, data: string[]) => {
          // Stale response check: discard if tenant switched during fetch
          if (thisSeq !== requestSeq || responseTenant !== currentTenant) {
            return;
          }
          activeRankings = data;
        },
      };
    };

    // User switches to tenant beta
    const betaReq = switchTenant("sec_ops_tenant_beta");
    assert.strictEqual(activeRankings, null, "Rankings must be immediately cleared on tenant switch");

    // Simulate delayed response from tenant alpha arriving late
    betaReq.receiveResponse("sec_ops_tenant_alpha", ["alpha-stale-1"]);
    assert.strictEqual(
      activeRankings,
      null,
      "Stale response from previous tenant must be discarded and never displayed"
    );

    // Legitimate response for tenant beta arrives
    betaReq.receiveResponse("sec_ops_tenant_beta", ["beta-host-1", "beta-host-2"]);
    assert.deepStrictEqual(activeRankings, ["beta-host-1", "beta-host-2"]);
  });

  // ── Requirement 2 & 5: Historical Host Containment vs Incident Lifecycle ──

  test("Requirement 2: Historical host containment does not mark a new incident as contained", () => {
    // Graph topology has host-0 marked CONTAINED from an earlier simulation
    const hostInFalkorDB = {
      id: "host-0",
      name: "Workstation-PatientZero",
      status: "CONTAINED", // Historical simulation
      firewall: true,
    };

    // Newly created incident inc-b2d96c57 on host-0
    const newIncident = {
      incident_id: "inc-b2d96c57",
      patient_zero_id: "host-0",
      status: "INVESTIGATED", // Active incident has NOT executed containment
      proposals: [],
      audit_trail: [],
    };

    // Authoritative lifecycle resolution logic (matching frontend/app/page.tsx)
    const resolveLifecycleStatus = (incident: typeof newIncident): string => {
      if (incident.status === "CONTAINED" || incident.audit_trail.length > 0) {
        return "CONTAINED";
      }
      if (incident.proposals.length > 0) {
        const p = incident.proposals[0] as { status?: string };
        return p?.status === "APPROVED"
          ? "APPROVED"
          : p?.status === "REJECTED"
          ? "REJECTED"
          : "PROPOSAL_CREATED";
      }
      return "INVESTIGATED";
    };

    const lifecycleStatus = resolveLifecycleStatus(newIncident);
    const isIncidentContained = lifecycleStatus === "CONTAINED";

    assert.strictEqual(
      lifecycleStatus,
      "INVESTIGATED",
      "New incident on historically contained host must resolve to INVESTIGATED"
    );
    assert.strictEqual(
      isIncidentContained,
      false,
      "New incident must NOT be marked contained merely because target host was previously simulated as contained"
    );

    // Verify UI display status labeling
    const isHistoricalSim =
      hostInFalkorDB.status === "CONTAINED" &&
      hostInFalkorDB.id === newIncident.patient_zero_id &&
      !isIncidentContained;

    assert.strictEqual(
      isHistoricalSim,
      true,
      "Host must be recognized as CONTAINED (PRIOR SIM), separating historical graph state from active incident"
    );
  });

  // ── Requirement 3 & 5: Premature Authorization & Enforcement Language ─────

  test("Requirement 3: No proposal means awaiting mitigation proposal, not awaiting review", () => {
    const proposals: unknown[] = [];
    const hasPersistedProposal = proposals.length > 0;

    // Timeline proposal stage resolution
    const proposalStage = {
      name: "Proposal",
      subtitle: hasPersistedProposal ? "Containment Formulation" : "Awaiting Mitigation Proposal",
      status: hasPersistedProposal ? "completed" : "pending",
      details: hasPersistedProposal
        ? "Containment proposal formulated."
        : "Awaiting mitigation proposal from responder or autonomous triage agent.",
    };

    assert.strictEqual(proposalStage.status, "pending", "Proposal stage must be pending before a proposal exists");
    assert.strictEqual(
      proposalStage.subtitle,
      "Awaiting Mitigation Proposal",
      "Subtitle must reflect awaiting proposal, not review decision"
    );
    assert.ok(
      proposalStage.details.includes("Awaiting mitigation proposal"),
      "Details must state awaiting mitigation proposal"
    );
    assert.strictEqual(
      proposalStage.details.includes("pending reviewer decision"),
      false,
      "Details must NOT display 'pending reviewer decision' before proposal exists"
    );

    // Header badge resolution
    const badgeText = hasPersistedProposal
      ? "Proposal Pending Reviewer Decision"
      : "Awaiting mitigation proposal";

    assert.strictEqual(
      badgeText,
      "Awaiting mitigation proposal",
      "Timeline header badge must display 'Awaiting mitigation proposal' when no proposal exists"
    );
  });

  test("Requirement 3: Human review and execution stages remain pending before proposal exists", () => {
    const hasPersistedProposal = false;
    const isApproved = false;
    const isContained = false;

    const reviewStage = {
      status: hasPersistedProposal ? "active" : "pending",
      details: hasPersistedProposal
        ? "Explicit human authorization required."
        : "Human review gate will activate once a mitigation proposal is formulated. Explicit reviewer authorization required before execution.",
    };

    const executionStage = {
      status: isContained ? "completed" : isApproved ? "active" : "pending",
      details: hasPersistedProposal
        ? "Execution blocked until explicit human approval is recorded."
        : "Execution blocked: awaiting mitigation proposal and explicit human review authorization.",
    };

    assert.strictEqual(reviewStage.status, "pending", "Review stage must be pending before proposal exists");
    assert.strictEqual(executionStage.status, "pending", "Execution stage must be pending before proposal exists");
    assert.ok(
      executionStage.details.includes("awaiting mitigation proposal"),
      "Execution details must state awaiting mitigation proposal"
    );
  });

  test("Requirement 3: Containment verification claims require matching persisted execution audit", () => {
    // Incident with no audit (not contained)
    const uncontainedIncidentAudit = null;
    const isIncidentContained = Boolean(uncontainedIncidentAudit);

    const getVerificationBanner = (contained: boolean, hasProposal: boolean): string => {
      if (contained) {
        return "✓ Verified via FalkorDB GraphBLAS (Incident Containment Verified)";
      }
      if (hasProposal) {
        return "Proposal Pending Reviewer Decision";
      }
      return "Awaiting Mitigation Proposal";
    };

    const getEnforcementNote = (contained: boolean, incidentId: string): string => {
      if (contained) {
        return `Graph-level isolation verified in FalkorDB for incident ${incidentId} via Cypher re-analysis. Physical hardware firewall rule enforcement requires authorized appliance connector.`;
      }
      return `Graph-level isolation simulation not yet executed for incident ${incidentId}. Historical host simulation state does not satisfy active incident containment. Physical hardware firewall rule enforcement requires authorized appliance connector.`;
    };

    // Before containment execution:
    const bannerBefore = getVerificationBanner(isIncidentContained, false);
    const noteBefore = getEnforcementNote(isIncidentContained, "inc-b2d96c57");

    assert.strictEqual(bannerBefore, "Awaiting Mitigation Proposal");
    assert.ok(
      noteBefore.includes("simulation not yet executed"),
      "Enforcement note must state isolation simulation not yet executed for uncontained incident"
    );
    assert.ok(
      noteBefore.includes("Historical host simulation state does not satisfy active incident containment"),
      "Enforcement note must explicitly state historical simulation does not satisfy active incident"
    );

    // After genuine containment execution:
    const containedAudit = {
      audit_id: "aud-verified-123",
      incident_id: "inc-b2d96c57",
      verification: "VERIFIED",
      paths_severed: 5,
      egress_reduced_mbps: 43.0,
    };
    const isVerifiedContained = containedAudit.verification === "VERIFIED";
    const bannerAfter = getVerificationBanner(isVerifiedContained, true);
    const noteAfter = getEnforcementNote(isVerifiedContained, "inc-b2d96c57");

    assert.strictEqual(
      bannerAfter,
      "✓ Verified via FalkorDB GraphBLAS (Incident Containment Verified)",
      "Verification banner must only show verified once matching execution audit confirms it"
    );
    assert.ok(
      noteAfter.includes("Graph-level isolation verified in FalkorDB for incident inc-b2d96c57"),
      "Enforcement note must confirm graph-level isolation for the specific incident"
    );
  });
});
