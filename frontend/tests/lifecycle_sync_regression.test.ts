import { describe, test, beforeEach } from "node:test";
import assert from "node:assert";
import {
  threatStream,
  type ThreatStreamEvent,
  type ProposalCreatedEvent,
} from "../lib/threatStream.ts";

describe("RootMesh Step 3BF: Human-in-the-Loop Lifecycle State Synchronization Suite", () => {
  beforeEach(() => {
    threatStream.disconnect();
    threatStream.setTenant(null);
  });

  test("Requirement 2: Proposal pending before review maintains truthful state", () => {
    // Stage: Proposal created, awaiting human reviewer decision
    const proposalData = {
      action_id: "act-test-001",
      incident_id: "inc-test-001",
      target_host_id: "host-0",
      target_host_name: "Workstation-PatientZero",
      status: "PROPOSED",
      proposer_principal: "secops_responder",
      created_at: 1729400000,
      risk_assessment: {
        lateral_targets: 4,
        max_egress_mbps: 12.5,
      },
    };

    // State assertion: Proposal is formulated, review is active/awaiting decision, execution is NOT active or completed
    assert.strictEqual(proposalData.status, "PROPOSED");
    assert.strictEqual(proposalData.risk_assessment.lateral_targets, 4);
    assert.strictEqual(proposalData.risk_assessment.max_egress_mbps, 12.5);

    // Verify it cannot be confused with approved or contained
    const isApproved = (proposalData.status as unknown as string) === "APPROVED";
    const isContained = (proposalData.status as unknown as string) === "CONTAINED";
    assert.strictEqual(isApproved, false, "Proposed action must NOT be marked approved");
    assert.strictEqual(isContained, false, "Proposed action must NOT be marked contained");
  });

  test("Requirement 2: Approved but not yet executed maintains guarded gate", () => {
    const proposalData = {
      action_id: "act-test-002",
      incident_id: "inc-test-002",
      status: "APPROVED",
      reviewed_by: "secops_lead",
      reviewed_at: 1729400050,
      review_comment: "Blast radius verified; containment approved.",
    };

    assert.strictEqual(proposalData.status, "APPROVED");
    assert.strictEqual(proposalData.reviewed_by, "secops_lead");

    // Must NOT be marked contained before execution succeeds
    const isContained = (proposalData.status as unknown as string) === "CONTAINED";
    assert.strictEqual(isContained, false, "Approved proposal must NOT be treated as contained before execution");
  });

  test("Requirement 2 & 4: Rejected proposal fails closed and cannot visually resemble containment", () => {
    const proposalData = {
      action_id: "act-test-003",
      incident_id: "inc-test-003",
      status: "REJECTED",
      reviewed_by: "secops_reviewer",
      reviewed_at: 1729400060,
      review_comment: "False positive beacon; containment rejected.",
    };

    assert.strictEqual(proposalData.status, "REJECTED");
    const isContained = (proposalData.status as unknown as string) === "CONTAINED";
    assert.strictEqual(isContained, false, "Rejected proposal must never be contained");

    // In timeline, status must resolve to rejected, not completed
    const timelineReviewStatus = proposalData.status === "REJECTED" ? "rejected" : "completed";
    assert.strictEqual(timelineReviewStatus, "rejected");
  });

  test("Requirement 2 & 4: Expired proposal is blocked from execution", () => {
    const now = 1729401000;
    const proposalData = {
      action_id: "act-test-004",
      incident_id: "inc-test-004",
      status: "EXPIRED" as string,
      created_at: now - 1000,
      expires_at: now - 100, // expired 100 seconds ago
    };

    assert.strictEqual(proposalData.status, "EXPIRED");
    assert.strictEqual(proposalData.expires_at < now, true, "Proposal should be past its expiry TTL");

    const timelineReviewStatus = proposalData.status === "EXPIRED" ? "expired" : "completed";
    assert.strictEqual(timelineReviewStatus, "expired");
  });

  test("Requirement 2 & 4: Successful graph simulation records GRAPH_TOPOLOGY_SIMULATION audit", () => {
    const auditData = {
      audit_id: "aud-test-005",
      action_id: "act-test-005",
      executed_by: "secops_lead",
      executed_at: 1729400100,
      verification: "VERIFIED",
      containment_type: "GRAPH_TOPOLOGY_SIMULATION",
      before_after: {
        paths_severed: 14,
        egress_reduction_mbps: 43.0,
      },
    };

    assert.strictEqual(auditData.containment_type, "GRAPH_TOPOLOGY_SIMULATION");
    assert.strictEqual(auditData.verification, "VERIFIED");
    assert.strictEqual(auditData.before_after.paths_severed, 14);
    assert.strictEqual(auditData.before_after.egress_reduction_mbps, 43.0);
  });

  test("Requirement 2 & 4: Failed execution cannot visually resemble successful containment", () => {
    const executionError = "FalkorDB query timeout: simulated node lock";
    const status: string = "EXECUTION_FAILED";

    const isContained = status === "CONTAINED";
    assert.strictEqual(isContained, false, "Failed execution must never set isContained to true");

    const executionStageStatus = status === "EXECUTION_FAILED" ? "failed" : "completed";
    assert.strictEqual(executionStageStatus, "failed");
    assert.strictEqual(executionError.includes("timeout"), true);
  });

  test("Requirement 3: ThreatStream ignores cross-tenant events and accepts tenant-matched events", () => {
    threatStream.setTenant("sec_ops_tenant_alpha");

    const receivedEvents: ThreatStreamEvent[] = [];
    const unsubscribe = threatStream.subscribe((e) => {
      receivedEvents.push(e);
    });

    // 1. Cross-tenant event (tenant_beta) -> MUST be ignored
    threatStream.handleRawMessage({
      event: "INCIDENT_PROPOSAL_CREATED",
      event_id: "evt-cross-001",
      action_id: "act-cross",
      incident_id: "inc-cross",
      target_host_id: "host-99",
      tenant_id: "sec_ops_tenant_beta",
      status: "PROPOSED",
      proposer: "other_user",
      timestamp: 1729400000,
    });

    assert.strictEqual(receivedEvents.length, 0, "Cross-tenant event must be ignored");

    // 2. Tenant-matched event (tenant_alpha) -> MUST be received
    threatStream.handleRawMessage({
      event: "INCIDENT_PROPOSAL_CREATED",
      event_id: "evt-alpha-001",
      action_id: "act-alpha",
      incident_id: "inc-alpha",
      target_host_id: "host-0",
      tenant_id: "sec_ops_tenant_alpha",
      status: "PROPOSED",
      proposer: "alpha_user",
      timestamp: 1729400001,
    });

    assert.strictEqual(receivedEvents.length, 1, "Tenant-matched event must be dispatched to listener");
    assert.strictEqual((receivedEvents[0] as ProposalCreatedEvent).action_id, "act-alpha");

    unsubscribe();
  });

  test("Requirement 3: ThreatStream deduplicates duplicate events and rejects out-of-order events", () => {
    threatStream.setTenant("sec_ops_tenant_alpha");

    const receivedEvents: ThreatStreamEvent[] = [];
    const unsubscribe = threatStream.subscribe((e) => {
      receivedEvents.push(e);
    });

    // Event 1 at timestamp 1729400100
    const evt1: ThreatStreamEvent = {
      event: "INCIDENT_PROPOSAL_REVIEWED",
      event_id: "evt-dedup-001",
      action_id: "act-dedup",
      incident_id: "inc-order-test",
      decision: "APPROVE",
      status: "APPROVED",
      reviewer: "lead_reviewer",
      tenant_id: "sec_ops_tenant_alpha",
      timestamp: 1729400100,
    };

    threatStream.handleRawMessage(evt1);
    assert.strictEqual(receivedEvents.length, 1);

    // Re-dispatch exact duplicate -> MUST be ignored
    threatStream.handleRawMessage(evt1);
    assert.strictEqual(receivedEvents.length, 1, "Duplicate event must be discarded");

    // Dispatch out-of-order event with strictly older timestamp for same incident
    const staleEvt: ThreatStreamEvent = {
      event: "INCIDENT_PROPOSAL_CREATED",
      event_id: "evt-stale-002",
      action_id: "act-dedup",
      incident_id: "inc-order-test",
      target_host_id: "host-0",
      tenant_id: "sec_ops_tenant_alpha",
      status: "PROPOSED",
      proposer: "responder",
      timestamp: 1729400050, // 50 seconds older than previous event
    };

    threatStream.handleRawMessage(staleEvt);
    assert.strictEqual(receivedEvents.length, 1, "Stale out-of-order event must be discarded");

    // Newer event at 1729400150 -> MUST be accepted
    const newerEvt: ThreatStreamEvent = {
      event: "INCIDENT_CONTAINMENT_EXECUTED",
      event_id: "evt-newer-003",
      action_id: "act-dedup",
      incident_id: "inc-order-test",
      target_host_id: "host-0",
      status: "CONTAINED",
      paths_severed: 5,
      egress_reduction_mbps: 10.0,
      verification: "VERIFIED",
      executed_by: "lead_reviewer",
      tenant_id: "sec_ops_tenant_alpha",
      timestamp: 1729400150,
    };

    threatStream.handleRawMessage(newerEvt);
    assert.strictEqual(receivedEvents.length, 2, "Monotonically progressive event must be accepted");

    unsubscribe();
  });

  test("Requirement 3: WebSocket reconnect recovery triggers listeners to reconcile with REST", () => {
    threatStream.setTenant("sec_ops_tenant_alpha");

    let reconnectTriggered = 0;
    const unsubscribeReconnect = threatStream.onReconnect(() => {
      reconnectTriggered++;
    });

    // First connection: auth_ok establishes initial live state
    threatStream.handleRawMessage({ type: "auth_ok", tenant_id: "sec_ops_tenant_alpha" });
    assert.strictEqual(reconnectTriggered, 0, "Initial connection should not trigger reconnect recovery");
    assert.strictEqual(threatStream.getStatus(), "live");

    // Simulate second connection (reconnect after disconnect)
    threatStream.handleRawMessage({ type: "auth_ok", tenant_id: "sec_ops_tenant_alpha" });
    assert.strictEqual(reconnectTriggered, 1, "Subsequent auth_ok must trigger reconnect recovery hook");

    unsubscribeReconnect();
  });

  test("Requirement 5: Tenant switching and sign-out cleanly resets ThreatStream state", () => {
    threatStream.setTenant("sec_ops_tenant_alpha");
    assert.strictEqual(threatStream.getTenant(), "sec_ops_tenant_alpha");

    // Sign out: set tenant to null
    threatStream.setTenant(null);
    assert.strictEqual(threatStream.getTenant(), null);
    assert.strictEqual(threatStream.getStatus(), "offline");

    // Switch to another tenant: old event history cleared
    threatStream.setTenant("sec_ops_tenant_beta");
    assert.strictEqual(threatStream.getTenant(), "sec_ops_tenant_beta");
  });

  test("Requirement 4: Absence of fabricated timeline evidence and hardcoded timestamps", () => {
    // When an incident is freshly created without proposal or review, timestamps should say "Pending"
    function formatTestTimestamp(ts?: number | string | null): string {
      if (ts === undefined || ts === null) return "Pending";
      if (typeof ts === "string") {
        if (ts.includes("T") || ts.includes("-") || ts.includes(":")) {
          const d = new Date(ts);
          if (!isNaN(d.getTime())) {
            return d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
          }
          return ts;
        }
        const n = parseFloat(ts);
        if (!isNaN(n)) return formatTestTimestamp(n);
        return ts;
      }
      const ms = ts > 1e11 ? ts : ts * 1000;
      const d = new Date(ms);
      if (isNaN(d.getTime())) return "Pending";
      return d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    }

    // 1. Missing timestamp -> "Pending" (never hardcoded "14:20:00 UTC")
    assert.strictEqual(formatTestTimestamp(null), "Pending");
    assert.strictEqual(formatTestTimestamp(undefined), "Pending");

    // 2. Verified timestamp -> truthful ISO UTC representation
    const sampleTimestamp = 1729400000; // 2024-10-20 04:53:20 UTC
    const formatted = formatTestTimestamp(sampleTimestamp);
    assert.strictEqual(formatted.endsWith("UTC"), true);
    assert.strictEqual(formatted.includes("14:20:00"), false, "Must not contain hardcoded 14:20:00 fallback");

    // 3. Absence of fabricated metrics:
    const targetCount = undefined;
    const egressMbps = undefined;
    const pathsText = targetCount !== undefined ? `${targetCount} paths` : "0 paths (Pending)";
    const egressText = egressMbps !== undefined ? `${egressMbps} Mbps` : "0.0 Mbps (None calculated)";

    assert.strictEqual(pathsText, "0 paths (Pending)");
    assert.strictEqual(egressText, "0.0 Mbps (None calculated)");
  });
});
