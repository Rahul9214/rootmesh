import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");

test("RootMesh Step 3BM.3: Final Customer Experience, Sticky Navigation & Public Walkthrough Suite", async (t) => {
  await t.test("Requirement 1: Strict Preservation of Protected Components", () => {
    // Check that GraphCanvas, SwipeableCardStack, and IncidentJourneyTimeline remain unchanged
    const graphCanvasPath = path.join(ROOT_DIR, "components", "GraphCanvas.tsx");
    const swipeablePath = path.join(ROOT_DIR, "components", "SwipeableCardStack.tsx");
    const timelinePath = path.join(ROOT_DIR, "components", "IncidentJourneyTimeline.tsx");

    assert.ok(fs.existsSync(graphCanvasPath), "GraphCanvas.tsx must exist");
    assert.ok(fs.existsSync(swipeablePath), "SwipeableCardStack.tsx must exist");
    assert.ok(fs.existsSync(timelinePath), "IncidentJourneyTimeline.tsx must exist");

    const graphCanvasSrc = fs.readFileSync(graphCanvasPath, "utf-8");
    const swipeableSrc = fs.readFileSync(swipeablePath, "utf-8");
    const timelineSrc = fs.readFileSync(timelinePath, "utf-8");

    // Verify key internal contracts are strictly intact
    assert.ok(graphCanvasSrc.includes("TOPOLOGY_NODES"), "GraphCanvas must preserve internal topology definitions");
    assert.ok(swipeableSrc.includes("motion.div") || swipeableSrc.includes("onDragEnd"), "SwipeableCardStack must preserve swipe gestures");
    assert.ok(timelineSrc.includes("incidentJourneyStages") || timelineSrc.includes("lifecycle"), "IncidentJourneyTimeline must preserve lifecycle timeline structure");
  });

  await t.test("Requirement 2: Sticky Glass Navigation Container and Overflow Rules", () => {
    const pagePath = path.join(ROOT_DIR, "app", "page.tsx");
    const globalsCssPath = path.join(ROOT_DIR, "app", "globals.css");

    const pageSrc = fs.readFileSync(pagePath, "utf-8");
    const globalsSrc = fs.readFileSync(globalsCssPath, "utf-8");

    // Must not use overflow-x-hidden on scroll ancestor, which breaks position: sticky
    assert.ok(globalsSrc.includes("overflow-x: clip;"), "globals.css must apply overflow-x: clip on body");
    assert.ok(pageSrc.includes("overflow-x-clip"), "Main container must use overflow-x-clip to prevent sticky breaking");
    assert.ok(!pageSrc.includes("<main className=\"min-h-screen bg-[#FAF7F2] text-[#2C221E] overflow-x-hidden"), "overflow-x-hidden must not be on main container");

    // TopNavbar must be sticky with warm ivory translucent glass
    assert.ok(pageSrc.includes("sticky top-0 z-50"), "TopNavbar must have sticky top-0 z-50");
    assert.ok(pageSrc.includes("backdrop-blur-md"), "TopNavbar must feature restrained backdrop blur");
    assert.ok(pageSrc.includes("bg-[#FAF7F2]/85"), "TopNavbar must feature warm ivory translucent background");

    // Anchor destinations must include scroll-mt to prevent navbar overlap
    assert.ok(pageSrc.includes("scroll-mt-20"), "Sections must include scroll-mt-20 to avoid sticking navbar overlap");
  });

  await t.test("Requirement 3: Organization-Friendly Display Labels & Tenant ID Isolation", () => {
    const pagePath = path.join(ROOT_DIR, "app", "page.tsx");
    const riskDeckPath = path.join(ROOT_DIR, "components", "RiskPrioritiesDeck.tsx");
    const heroPath = path.join(ROOT_DIR, "components", "HeroSection.tsx");
    const journeyPath = path.join(ROOT_DIR, "components", "InvestigationJourneyCanvas.tsx");

    const pageSrc = fs.readFileSync(pagePath, "utf-8");
    const riskDeckSrc = fs.readFileSync(riskDeckPath, "utf-8");
    const heroSrc = fs.readFileSync(heroPath, "utf-8");
    const journeySrc = fs.readFileSync(journeyPath, "utf-8");

    // Page must resolve friendly organization name and fail-closed to neutral 'Workspace'
    assert.ok(pageSrc.includes("organization?.name"), "page.tsx must resolve verified Clerk organization name");
    assert.ok(pageSrc.includes('"Workspace"'), "page.tsx must fallback to neutral Workspace label");

    // RiskPrioritiesDeck must not display raw hardcoded 'sec_ops_tenant_alpha' in copy
    assert.ok(!riskDeckSrc.includes('>{tenantId || "sec_ops_tenant_alpha"}</span>'), "RiskPrioritiesDeck must not render raw tenantId as primary user label");
    assert.ok(riskDeckSrc.includes("organizationName"), "RiskPrioritiesDeck must accept organizationName prop");

    // HeroSection must show Workspace name prominently and only show tenantId in advanced diagnostic details
    assert.ok(heroSrc.includes("organizationName"), "HeroSection must accept organizationName prop");
    assert.ok(journeySrc.includes("organizationName"), "InvestigationJourneyCanvas must accept organizationName prop");
  });

  await t.test("Requirement 4: Public Landing Experience & Privacy Boundaries", () => {
    const publicLandingPath = path.join(ROOT_DIR, "components", "PublicLandingExperience.tsx");
    assert.ok(fs.existsSync(publicLandingPath), "PublicLandingExperience.tsx must exist");

    const landingSrc = fs.readFileSync(publicLandingPath, "utf-8");

    // Must address core value narrative and questions
    assert.ok(landingSrc.includes("Understand connected exposure"), "Public landing must state core problem");
    assert.ok(landingSrc.includes("Understand Connected Exposure"), "Public landing must present outcome 1");
    assert.ok(landingSrc.includes("Investigate Potential Impact"), "Public landing must present outcome 2");
    assert.ok(landingSrc.includes("Coordinate a Reviewed Response"), "Public landing must present outcome 3");

    // Must not expose live private tenant data or internal IP addresses in marketing copy
    assert.ok(!landingSrc.includes("10.0.1."), "Public landing must not expose internal production subnet IP addresses");
    assert.ok(!landingSrc.includes("sec_ops_tenant_alpha"), "Public landing must not leak raw internal tenant IDs");
    assert.ok(!landingSrc.includes("FalkorDB cluster"), "Public landing must not leak database implementation identifiers");

    // Must clearly state product boundaries and simulation status
    assert.ok(landingSrc.includes("Human-in-the-Loop Safeguards"), "Public landing must explain human review requirement");
    assert.ok(landingSrc.includes("Graph Topology Simulation Mode"), "Public landing must state current graph simulation status");
  });

  await t.test("Requirement 5: Replayable Product Walkthrough Without Side Effects", () => {
    const walkthroughPath = path.join(ROOT_DIR, "components", "ProductWalkthroughReplay.tsx");
    assert.ok(fs.existsSync(walkthroughPath), "ProductWalkthroughReplay.tsx must exist");

    const walkthroughSrc = fs.readFileSync(walkthroughPath, "utf-8");

    // Must feature 5-stage conceptual progression
    assert.ok(walkthroughSrc.includes("Asset Selected"), "Walkthrough must include Stage 1: Asset Selected");
    assert.ok(walkthroughSrc.includes("Connections Analyzed"), "Walkthrough must include Stage 2: Connections Analyzed");
    assert.ok(walkthroughSrc.includes("Potential Impact Identified"), "Walkthrough must include Stage 3: Potential Impact Identified");
    assert.ok(walkthroughSrc.includes("Response Owner Resolved"), "Walkthrough must include Stage 4: Response Owner Resolved");
    assert.ok(walkthroughSrc.includes("Human Review Required"), "Walkthrough must include Stage 5: Human Review Required");

    // Must provide interactive controls
    assert.ok(walkthroughSrc.includes("Replay"), "Walkthrough must include Replay control");
    assert.ok(walkthroughSrc.includes("Pause") || walkthroughSrc.includes("Play"), "Walkthrough must include Play/Pause control");

    // Must respect reduced-motion and intersection-observer
    assert.ok(walkthroughSrc.includes("prefers-reduced-motion"), "Walkthrough must support prefers-reduced-motion");
    assert.ok(walkthroughSrc.includes("IntersectionObserver"), "Walkthrough must pause when scrolled off-screen");

    // Must not trigger backend mutation or network calls
    assert.ok(!walkthroughSrc.includes("fetch("), "Walkthrough must never call fetch or execute API requests");
    assert.ok(!walkthroughSrc.includes("/api/"), "Walkthrough must not reference backend endpoints");
  });

  await t.test("Requirement 6: Lifecycle Governance Guide Clarifying Stages 4–8", () => {
    const guidePath = path.join(ROOT_DIR, "components", "LifecycleGovernanceGuide.tsx");
    assert.ok(fs.existsSync(guidePath), "LifecycleGovernanceGuide.tsx must exist");

    const guideSrc = fs.readFileSync(guidePath, "utf-8");

    // Must clarify stages 4 through 8 strict operational prerequisites
    assert.ok(guideSrc.includes("Proposal"), "Must explain Stage 4 Proposal prerequisites");
    assert.ok(guideSrc.includes("Human Review"), "Must explain Stage 5 Human Review prerequisites");
    assert.ok(guideSrc.includes("Execution"), "Must explain Stage 6 Execution prerequisites");
    assert.ok(guideSrc.includes("Verification"), "Must explain Stage 7 Verification prerequisites");
    assert.ok(guideSrc.includes("Memory &amp; Audit") || guideSrc.includes("Memory"), "Must explain Stage 8 Memory & Audit prerequisites");

    // Must state that steps cannot turn green on time or animation alone
    assert.ok(guideSrc.includes("Fail-Closed Governance") || guideSrc.includes("pending"), "Must articulate fail-closed governance");
  });
});
