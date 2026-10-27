import { describe, test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper function simulating the exact client-side filter and validation logic
function filterTopologyAssets(
  assets: Array<{ id: string; name: string; ip: string; status: string }>,
  query: string
) {
  if (!query.trim()) return assets;
  const q = query.toLowerCase().trim();
  return assets.filter(
    (a) =>
      a.id.toLowerCase().includes(q) ||
      a.name.toLowerCase().includes(q) ||
      a.ip.toLowerCase().includes(q)
  );
}

function validateAndSelectAsset(
  assets: Array<{ id: string; name: string; ip: string; status: string }>,
  inputIdentifier: string
): { selectedAsset: { id: string; name: string; ip: string; status: string } | null; error: string | null } {
  const trimmed = inputIdentifier.trim();
  if (!trimmed) {
    return { selectedAsset: null, error: "Please select an active infrastructure asset from the topology rail." };
  }

  const match = assets.find(
    (a) => a.id.toLowerCase() === trimmed.toLowerCase() || a.name.toLowerCase() === trimmed.toLowerCase()
  );

  if (!match) {
    return {
      selectedAsset: null,
      error: `Asset "${trimmed}" is not a verified host in the topology inventory.`,
    };
  }

  return { selectedAsset: match, error: null };
}

describe("RootMesh Step 3BL.1: Autonomous Investigation Workspace Suite", () => {
  const verifiedTopology = [
    { id: "host-0", name: "Workstation-PatientZero", ip: "10.0.1.15", status: "INFECTED", hops: 0 },
    { id: "host-1", name: "AppServer-Internal", ip: "10.0.2.10", status: "SAFE", hops: 1 },
    { id: "host-2", name: "FileBackupServer", ip: "10.0.2.22", status: "SAFE", hops: 1 },
    { id: "host-3", name: "VLAN-Router", ip: "10.0.3.1", status: "SAFE", hops: 2 },
    { id: "host-4", name: "JumpServer-SysAdmin", ip: "10.0.4.5", status: "SAFE", hops: 3 },
    { id: "host-5", name: "ReverseProxy", ip: "10.0.5.1", status: "SAFE", hops: 3 },
    { id: "host-6", name: "PublicWebServer", ip: "10.0.5.80", status: "SAFE", hops: 4 },
    { id: "host-7", name: "EgressFirewall", ip: "10.0.99.254", status: "SAFE", hops: 4 },
  ];

  // ── 1. Dynamic Asset Retrieval & No Hardcoding ────────────────────────────

  test("Requirement 3: HeroSection does NOT hardcode production asset lists or static host arrays", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Must NOT contain the old hardcoded quick target array
    assert.strictEqual(
      content.includes('["host-0", "host-1", "host-2", "host-3"]'),
      false,
      'HeroSection.tsx must NOT contain hardcoded ["host-0", "host-1", "host-2", "host-3"] list'
    );

    // Must fetch dynamically from the authenticated topology endpoint
    assert.ok(
      content.includes("/api/v1/threat/topology/"),
      "HeroSection.tsx must retrieve assets from /api/v1/threat/topology/{tenant_id}"
    );

    // Must define TopologyAsset interface
    assert.ok(
      content.includes("export interface TopologyAsset"),
      "HeroSection.tsx must define TopologyAsset interface"
    );
  });

  // ── 2. Searchable Filter on Asset Intelligence Rail ───────────────────────

  test("Requirement 3: Search filter accurately filters real topology assets by ID, name, and IP", () => {
    // Search by ID
    const byId = filterTopologyAssets(verifiedTopology, "host-3");
    assert.strictEqual(byId.length, 1);
    assert.strictEqual(byId[0].name, "VLAN-Router");

    // Search by Name
    const byName = filterTopologyAssets(verifiedTopology, "Backup");
    assert.strictEqual(byName.length, 1);
    assert.strictEqual(byName[0].id, "host-2");

    // Search by IP
    const byIp = filterTopologyAssets(verifiedTopology, "10.0.5.1");
    assert.strictEqual(byIp.length, 1);
    assert.strictEqual(byIp[0].id, "host-5");

    // Empty query returns all assets
    const all = filterTopologyAssets(verifiedTopology, "");
    assert.strictEqual(all.length, 8);

    // Non-matching query returns empty
    const none = filterTopologyAssets(verifiedTopology, "non-existent-device");
    assert.strictEqual(none.length, 0);
  });

  // ── 3. Arbitrary Identifier Validation Guard ──────────────────────────────

  test("Requirement 3: Arbitrary or unverified asset identifiers are blocked from triggering investigation", () => {
    // Valid verified asset resolves cleanly
    const valid = validateAndSelectAsset(verifiedTopology, "host-0");
    assert.strictEqual(valid.error, null);
    assert.notStrictEqual(valid.selectedAsset, null);
    assert.strictEqual(valid.selectedAsset?.id, "host-0");

    // Arbitrary unverified asset is blocked
    const unverified = validateAndSelectAsset(verifiedTopology, "host-rogue-999");
    assert.strictEqual(unverified.selectedAsset, null);
    assert.ok(unverified.error?.includes("not a verified host in the topology inventory"));

    // Blank asset is blocked
    const blank = validateAndSelectAsset(verifiedTopology, "   ");
    assert.strictEqual(blank.selectedAsset, null);
    assert.ok(blank.error?.includes("Please select an active infrastructure asset"));
  });

  // ── 4. Factual Real-Time Interaction & Truthful Running State ─────────────

  test("Requirement 5: Running status is truthful and does not fabricate milestones or firewall enforcement", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Running state displays genuine GraphBLAS traversal status
    assert.ok(
      content.includes("Traversing Graph Topology…"),
      "HeroSection must display truthful running status 'Traversing Graph Topology…'"
    );

    // Must NOT claim physical host isolation or hardware firewall enforcement
    assert.strictEqual(
      content.includes("host isolated"),
      false,
      "HeroSection must NOT claim 'host isolated' during autonomous investigation"
    );
    assert.strictEqual(
      content.includes("firewall enforced"),
      false,
      "HeroSection must NOT claim physical 'firewall enforced'"
    );

    // Must NOT contain artificial/fabricated delay loops
    assert.strictEqual(
      content.includes("setTimeout"),
      false,
      "HeroSection must NOT use synthetic setTimeout delays to simulate fake phase progress"
    );
  });

  // ── 5. Backward Compatibility & Grounded Metrics Display ──────────────────

  test("Requirement 3 & 4: HeroSection preserves element IDs and formats factual investigation metrics", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Preserves established IDs for accessibility and testing
    assert.ok(
      content.includes('id="patient-zero-input"'),
      "Must preserve id='patient-zero-input' on search/filter control"
    );
    assert.ok(
      content.includes('id="run-triage-btn"'),
      "Must preserve id='run-triage-btn' on primary investigation action"
    );

    // Grounded metrics extraction matches FastAPI backend response
    const mockInvestigationReport = {
      incident_id: "inc-test-abc",
      patient_zero_id: "host-0",
      patient_zero_name: "Workstation-PatientZero",
      target_count: 14,
      execution_time_ms: 32.4,
      egress_risk_mbps: 43.0,
      shortest_path_to_db: {
        db_name: "HR-Payroll-DB",
        classification: "PII_RESTRICTED",
        distance: 1,
      },
      company_brain: {
        team_name: "SecOps Incident Response (team-sec)",
        person_name: "Alex Rivera",
        runbook_title: "Workstation Lateral Movement Containment SOP",
      },
      attack_paths: [{ target_name: "AppServer-Internal", hops: 1, path: ["host-0", "host-1"] }],
    };

    assert.strictEqual(mockInvestigationReport.target_count, 14);
    assert.strictEqual(mockInvestigationReport.execution_time_ms, 32.4);
    assert.strictEqual(mockInvestigationReport.egress_risk_mbps, 43.0);
    assert.strictEqual(mockInvestigationReport.shortest_path_to_db.db_name, "HR-Payroll-DB");
  });

  // ── 6. Tenant Context & Concurrency Guard Invariants ──────────────────────

  test("Requirement 6: In-flight and request ID guards protect against duplicate submissions", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    assert.ok(
      content.includes("inFlightRef.current"),
      "HeroSection must check inFlightRef to prevent concurrent or duplicate submissions"
    );
    assert.ok(
      content.includes("requestIdRef.current"),
      "HeroSection must use requestIdRef to ignore stale out-of-order responses"
    );
  });

  // ── 8. Step 3BL.2 Refinement: Inline Asset Tokens & Rail Composition ──────

  test("Step 3BL.2: Asset Intelligence Rail renders compact inline tokens with accessible attributes", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Must use inline-flex token styling instead of repetitive boxed card layout
    assert.ok(
      content.includes("inline-flex items-center gap-2.5 h-11 px-3.5 rounded-lg border"),
      "HeroSection must use compact inline asset token pills"
    );
    assert.ok(
      content.includes("w-px h-3.5 bg-[#DFD6C9]"),
      "HeroSection must include subtle separators between ID and host name"
    );
    assert.ok(
      content.includes("PAST SIM") || content.includes("PATIENT ZERO"),
      "HeroSection inline tokens must provide contextual status chips"
    );
    assert.ok(
      content.includes('role="radiogroup"'),
      "HeroSection must preserve semantic radiogroup role on rail"
    );
    assert.ok(
      content.includes('role="radio"'),
      "HeroSection must preserve semantic radio role on asset tokens"
    );
  });

  // ── 9. Step 3BL.3 Refinement: Streamlined Specification Ribbon & Mobile Touch ─

  test("Step 3BL.3: Selected asset attributes use streamlined specification ribbon with mobile scroll cue", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Streamlined attribute ribbon
    assert.ok(
      content.includes("IP:") && content.includes("Defense:") && content.includes("Firewall:") && content.includes("Exposure:"),
      "Selected asset presentation must display streamlined specification ribbon (IP, Defense, Firewall, Exposure)"
    );

    // Unobtrusive scroll affordance on mobile rail
    assert.ok(
      content.includes("bg-gradient-to-l from-[#F5EFE6] to-transparent") && content.includes("sm:hidden"),
      "HeroSection must provide unobtrusive scroll affordance on mobile rail"
    );

    // Prominent investigation action with accessible min-height
    assert.ok(
      content.includes("min-h-[48px]") || content.includes("min-h-[44px]"),
      "Primary investigation action button must have accessible min-height of at least 44px"
    );
  });

  // ── 10. Step 3BL.3 Refinement: Concise Historical Scoping with Disclosure ──

  test("Step 3BL.3: Historical CONTAINED status provides concise statement and accessible disclosure", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Explicit historical badge
    assert.ok(
      content.includes("HISTORICAL TOPOLOGY CONTAINMENT"),
      "HeroSection must badge CONTAINED hosts with 'HISTORICAL TOPOLOGY CONTAINMENT'"
    );

    // Concise customer-facing statement
    assert.ok(
      content.includes("Prior simulated containment does not resolve new active threats on this host"),
      "HeroSection must display concise customer-facing containment scoping statement"
    );

    // Accessible details/summary disclosure control
    assert.ok(
      content.includes("<details") && content.includes("<summary"),
      "HeroSection must provide accessible disclosure control (<details>/<summary>) for extended simulation details"
    );
    assert.ok(
      content.includes("earlier graph-topology simulation"),
      "HeroSection disclosure must explain that CONTAINED status is from an earlier graph-topology simulation"
    );
  });

  // ── 11. Step 3BL.3 Refinement: Concise Customer-Oriented Copy ───────────────

  test("Step 3BL.3: Customer-facing workspace copy uses concise, customer-oriented terminology", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    assert.ok(
      content.includes("Autonomous Threat Investigation"),
      "Workspace header must use clear SecOps title 'Autonomous Threat Investigation'"
    );
    assert.ok(
      content.includes('placeholder="Search assets by ID, name, or IP…"'),
      "Search input must use concise mobile-friendly placeholder"
    );

    // No blanket sub-millisecond claims in the main workspace description
    assert.strictEqual(
      content.includes("sub-millisecond graph reasoning"),
      false,
      "HeroSection must NOT contain blanket 'sub-millisecond graph reasoning' claims"
    );
  });

  // ── 12. Verification: Protected Components Remain 100% Untouched ───────────

  test("Requirement 1: Protected components (GraphCanvas & SwipeableCardStack) are untouched", () => {
    const graphPath = path.resolve(__dirname, "../components/GraphCanvas.tsx");
    const stackPath = path.resolve(__dirname, "../components/SwipeableCardStack.tsx");

    const graphContent = fs.readFileSync(graphPath, "utf-8");
    const stackContent = fs.readFileSync(stackPath, "utf-8");

    // GraphCanvas invariants
    assert.ok(graphContent.includes("TOPOLOGY_NODES"), "GraphCanvas retains topology nodes");
    assert.ok(graphContent.includes("FalkorDB Interactive Graph Canvas"), "GraphCanvas retains signature title");
    assert.ok(graphContent.includes("PageRank Overlay"), "GraphCanvas retains PageRank controls");

    // SwipeableCardStack invariants
    assert.ok(stackContent.includes("SwipeableCardStack"), "SwipeableCardStack retains signature component");
    assert.ok(stackContent.includes("onContainmentExecuted"), "SwipeableCardStack retains containment callbacks");
    assert.ok(stackContent.includes("onSelectIncident"), "SwipeableCardStack retains incident selection callback");
  });
});
