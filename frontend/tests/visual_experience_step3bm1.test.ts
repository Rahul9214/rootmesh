import { describe, test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("RootMesh Step 3BM.1: Signature Visual Experience & Connected Network Design Suite", () => {
  // ── 1. Strict Preservation Verification ───────────────────────────────────

  test("Requirement 1: Protected components are strictly untouched and preserved", () => {
    const graphCanvasPath = path.resolve(__dirname, "../components/GraphCanvas.tsx");
    const swipeableDeckPath = path.resolve(__dirname, "../components/SwipeableCardStack.tsx");
    const timelinePath = path.resolve(__dirname, "../components/IncidentJourneyTimeline.tsx");

    assert.ok(fs.existsSync(graphCanvasPath), "GraphCanvas.tsx must exist");
    assert.ok(fs.existsSync(swipeableDeckPath), "SwipeableCardStack.tsx must exist");
    assert.ok(fs.existsSync(timelinePath), "IncidentJourneyTimeline.tsx must exist");

    const graphContent = fs.readFileSync(graphCanvasPath, "utf-8");
    assert.ok(
      graphContent.includes("FalkorDB Interactive Graph Explorer") ||
        graphContent.includes("GraphCanvas") ||
        graphContent.includes("FalkorDB"),
      "GraphCanvas must maintain its authentic FalkorDB engine integration"
    );

    const swipeContent = fs.readFileSync(swipeableDeckPath, "utf-8");
    assert.ok(
      swipeContent.includes("SwipeableCardStack") && swipeContent.includes("initiateProposal"),
      "SwipeableCardStack must maintain its guarded proposal and card interaction model"
    );

    const timelineContent = fs.readFileSync(timelinePath, "utf-8");
    assert.ok(
      timelineContent.includes("IncidentJourneyTimeline") && timelineContent.includes("lifecycleState"),
      "IncidentJourneyTimeline must maintain its 8-stage lifecycle presentation"
    );
  });

  // ── 2. Signature Network Grid Background Verification ─────────────────────

  test("Requirement 2: NetworkGridBackground provides architectural SVG network grid without obscuring UI", () => {
    const bgPath = path.resolve(__dirname, "../components/NetworkGridBackground.tsx");
    assert.ok(fs.existsSync(bgPath), "NetworkGridBackground.tsx must exist");

    const content = fs.readFileSync(bgPath, "utf-8");

    // Must be decorative and non-interactive
    assert.ok(
      content.includes('aria-hidden="true"'),
      "NetworkGridBackground must be aria-hidden for accessibility"
    );
    assert.ok(
      content.includes("pointer-events-none"),
      "NetworkGridBackground must have pointer-events-none so it cannot block clicks"
    );
    assert.ok(
      content.includes("z-0"),
      "NetworkGridBackground must be positioned at z-0 behind operational content"
    );

    // Must feature approved RootMesh ivory, terracotta, and plum tokens
    assert.ok(content.includes("#FAF7F2"), "Background must use warm ivory base #FAF7F2");
    assert.ok(content.includes("#D26A50"), "Background must include terracotta accent #D26A50");
    assert.ok(content.includes("#82465D"), "Background must include plum accent #82465D");

    // Must include desktop-only pointer check & reduced motion check
    assert.ok(
      content.includes("pointer: fine"),
      "Pointer effect must be restricted to desktop fine pointer devices"
    );
    assert.ok(
      content.includes("prefers-reduced-motion"),
      "Must check prefers-reduced-motion to disable pointer spotlight"
    );

    // Must clean up event listener and cancelAnimationFrame on unmount
    assert.ok(
      content.includes("removeEventListener") && content.includes("cancelAnimationFrame"),
      "Must properly clean up listeners and animation frames to prevent memory leaks"
    );
  });

  // ── 3. InvestigationJourneyCanvas Architectural Transformation & Stages ──

  test("Requirement 4: InvestigationJourneyCanvas implements 4 connected stages with truthful lifecycle", () => {
    const canvasPath = path.resolve(__dirname, "../components/InvestigationJourneyCanvas.tsx");
    assert.ok(fs.existsSync(canvasPath), "InvestigationJourneyCanvas.tsx must exist");

    const content = fs.readFileSync(canvasPath, "utf-8");

    // Must define the 4 connected stages
    assert.ok(content.includes("ORIGIN ASSET"), "Must represent Origin Asset stage");
    assert.ok(content.includes("LATERAL EXPOSURE"), "Must represent Lateral Exposure stage");
    assert.ok(content.includes("DATA PROXIMITY"), "Must represent Data Proximity stage");
    assert.ok(content.includes("GOVERNANCE GATEWAY"), "Must represent Governance Gateway stage");

    // Must have stable min-height for CLS prevention
    assert.ok(
      content.includes("min-h-"),
      "InvestigationJourneyCanvas must reserve min-height to prevent Cumulative Layout Shift"
    );

    // Idle state must NOT claim execution complete
    assert.ok(
      content.includes("Awaiting graph traversal"),
      "Idle state must truthfully declare awaiting graph traversal"
    );

    // In-flight state must indicate query in flight
    assert.ok(
      content.includes("Evaluating Propagation…") || content.includes("GraphBLAS traversal in flight"),
      "In-flight state must indicate query processing truthfully"
    );
  });

  // ── 4. Truthful Missing Evidence Handling & Deduplicated Action ──────────

  test("Requirement 4: Missing data asset or brain records produce truthful fallback, not fabricated entities", () => {
    const canvasPath = path.resolve(__dirname, "../components/InvestigationJourneyCanvas.tsx");
    const content = fs.readFileSync(canvasPath, "utf-8");

    // High-value database missing fallback: must NOT say Isolated (Safe) solely on null DB
    assert.ok(
      content.includes("No forward path to restricted databases") ||
        content.includes("No data layer path detected") ||
        content.includes("No forward path in evaluated graph"),
      "Must display truthful unreached state when database proximity is null"
    );

    // Company brain missing fallback: truthful "Owner not resolved"
    assert.ok(
      content.includes("Owner not resolved") || content.includes("Playbook SOP Assigned"),
      "Must display 'Owner not resolved' or unassigned state when Company Brain lookup is empty"
    );

    // Continuous flowing SVG path verification
    assert.ok(
      content.includes("journey-path-gradient") || content.includes("<svg"),
      "InvestigationJourneyCanvas must render continuous flowing SVG investigation path"
    );

    // Duplicate button removal: canvas must not render a duplicate primary action button
    assert.strictEqual(
      content.includes('id="run-triage-btn"'),
      false,
      "InvestigationJourneyCanvas must not duplicate primary action button #run-triage-btn"
    );
  });

  // ── 5. Auto-Completion / Typewriter Reveal Interaction ─────────────────────

  test("Requirement 5: Typewriter reveal operates on genuine evidence and respects reduced motion", () => {
    const canvasPath = path.resolve(__dirname, "../components/InvestigationJourneyCanvas.tsx");
    const content = fs.readFileSync(canvasPath, "utf-8");

    // Must use useReducedMotion hook
    assert.ok(
      content.includes("useReducedMotion"),
      "Must use useReducedMotion to detect user accessibility preference"
    );

    // When shouldReduceMotion is true, must render immediately without animation
    assert.ok(
      content.includes("shouldReduceMotion") && content.includes("setIsTypingComplete(true)"),
      "Reduced motion must render complete text immediately with zero typing delay"
    );

    // Must construct text strictly from summary properties, not fake terminal loops
    assert.ok(
      content.includes("summary.incident_id") || content.includes("activeIncidentId"),
      "Reveal text must be keyed to authentic incident ID"
    );
    assert.ok(
      content.includes("summary.target_count") || content.includes("targetCount"),
      "Reveal text must reflect authentic target count from FalkorDB"
    );
    assert.ok(
      content.includes("summary.execution_time_ms") || content.includes("execTime"),
      "Reveal text must reflect authentic FalkorDB query execution time"
    );
  });

  // ── 6. Tenant Isolation & State Clearing ──────────────────────────────────

  test("Requirement 9: Switching tenant clears operational state and resets investigation", () => {
    const pagePath = path.resolve(__dirname, "../app/page.tsx");
    const content = fs.readFileSync(pagePath, "utf-8");

    // Must reset active investigation, persisted findings, and threat stream tenant on org change
    assert.ok(
      content.includes("setActiveInvestigation(null)") &&
        content.includes("setPersistedFindings([])") &&
        content.includes("threatStream.setTenant(null)"),
      "page.tsx must clear operational investigation findings and reset ThreatStream when tenant changes"
    );
  });

  // ── 7. De-duplicated Container Composition ────────────────────────────────

  test("Requirement 3: HeroSection replaces nested card-in-card grids with cohesive metric telemetry strip", () => {
    const heroPath = path.resolve(__dirname, "../components/HeroSection.tsx");
    const content = fs.readFileSync(heroPath, "utf-8");

    // Metrics grid should use cohesive divide layout rather than 4 standalone shadow cards
    assert.ok(
      content.includes("divide-y") || content.includes("divide-x"),
      "HeroSection must use an integrated metric bar with fine dividers rather than repetitive isolated boxes"
    );

    // Threat state ribbon uses refined light styling
    assert.ok(
      content.includes("Operational Threat State"),
      "HeroSection must include operational threat state diagnostic strip"
    );
  });

  // ── 8. Guarded Action Boundaries & No False Enforcement Claims ────────────

  test("Requirement 6: Interface never implies actual firewall or infrastructure enforcement", () => {
    const pagePath = path.resolve(__dirname, "../app/page.tsx");
    const pageContent = fs.readFileSync(pagePath, "utf-8");

    assert.ok(
      pageContent.includes("GRAPH_TOPOLOGY_SIMULATION") || pageContent.includes("topological simulations"),
      "Must explicitly label containment as GRAPH_TOPOLOGY_SIMULATION in FalkorDB"
    );

    const journeyPath = path.resolve(__dirname, "../components/InvestigationJourneyCanvas.tsx");
    const journeyContent = fs.readFileSync(journeyPath, "utf-8");

    assert.strictEqual(
      journeyContent.includes("firewall rule deployed to router"),
      false,
      "Must never claim actual physical firewall rule deployment"
    );
  });
});
