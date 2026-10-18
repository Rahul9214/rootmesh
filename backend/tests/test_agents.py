"""
RootMesh — Multi-Agent Swarm Unit & Integration Tests
Tests: TriageAgent, MitigationAgent, and MemoryAgent against FalkorDB.
"""
from __future__ import annotations

import pytest
from app.agents.triage import TriageAgent
from app.agents.mitigation import MitigationAgent
from app.agents.memory import MemoryAgent

TENANT_ID = "sec_ops_tenant_alpha"


@pytest.fixture
def triage_agent():
    return TriageAgent(tenant_id=TENANT_ID)


@pytest.fixture
def mitigation_agent():
    return MitigationAgent(tenant_id=TENANT_ID)


@pytest.fixture
def memory_agent():
    return MemoryAgent(tenant_id=TENANT_ID)


def test_triage_agent_resolves_host_and_paths(triage_agent):
    """Verify TriageAgent resolves metadata, CVEs, and multi-hop attack paths."""
    # Warm-up socket connection
    triage_agent.triage_host("host-0", max_hops=1)
    res = triage_agent.triage_host("host-0", max_hops=4)
    assert res["status"] == "TRIAGED"
    assert res["host"]["id"] == "host-0"
    assert res["host"]["name"] == "Workstation-PatientZero"
    assert "CVE-2017-0144" in res["host"]["cves"]
    assert res["target_count"] >= 1
    assert res["execution_time_ms"] < 250.0  # GraphBLAS SLA check under multi-task test load


def test_triage_agent_handles_unknown_host(triage_agent):
    """Verify TriageAgent gracefully handles non-existent host IDs."""
    res = triage_agent.triage_host("non-existent-host")
    assert res["status"] == "NOT_FOUND"


def test_mitigation_agent_assess_egress(mitigation_agent):
    """Verify MitigationAgent executes MaxFlow query to gateway firewall."""
    mitigation_agent.assess_egress_risk(source_id="host-0", sink_id="host-7")
    res = mitigation_agent.assess_egress_risk(source_id="host-0", sink_id="host-7")
    assert "max_egress_mbps" in res
    assert res["execution_time_ms"] < 250.0


def test_mitigation_agent_resolves_oncall(mitigation_agent):
    """Verify MitigationAgent resolves on-call responder for owned infrastructure (Track 3)."""
    responders = mitigation_agent.resolve_incident_responders("host-1")
    assert len(responders) >= 1
    assert responders[0]["responder"] == "Alex Rivera"
    assert "SecOps" in responders[0]["team"]


def test_mitigation_agent_executes_containment(mitigation_agent):
    """Verify MitigationAgent activates host firewall in FalkorDB graph."""
    res = mitigation_agent.execute_containment("host-0")
    assert res["status"] == "CONTAINED"
    assert res["firewall_active"] is True


def test_memory_agent_persists_and_recalls(memory_agent):
    """Verify MemoryAgent stores episodic findings and recalls them across sessions (Track 2)."""
    res = memory_agent.persist_finding(
        host_id="host-1",
        text="Suspicious outbound lateral movement observed by agent",
        severity="CRITICAL",
        session_id="agent-swarm-run-42",
    )
    assert res["finding_id"].startswith("find-")

    # Recall host memory
    history = memory_agent.recall_host_memory("host-1", limit=5)
    assert len(history) >= 1
    assert any("lateral movement" in f["text"] for f in history)

    # Multi-tenant isolation listing
    all_findings = memory_agent.list_all_tenant_findings(limit=10)
    assert len(all_findings) >= 1
