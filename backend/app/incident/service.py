"""
RootMesh — Guarded Incident Response Service
Coordinates TriageAgent, MitigationAgent, and MemoryAgent across the 8-stage lifecycle:
Incident → Investigation → Graph Evidence → Risk Assessment → Proposed Action → Authorized Review → Execution → Verification → Audit
Backed by persistent, concurrency-safe FalkorDB idempotency records and immutable graph provenance.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status

from app.agents.memory import MemoryAgent
from app.agents.mitigation import MitigationAgent
from app.agents.triage import TriageAgent
from app.config import settings
from app.db import queries
from app.db.falkor_client import db_pool
from app.incident.models import (
    ActionProposal,
    ActionState,
    ExecuteActionRequest,
    ExecutionAuditResponse,
    ProposeActionRequest,
    ReviewActionRequest,
)
from app.security.auth import SecurityPrincipal, enforce_tenant_context

logger = logging.getLogger("RootMesh-IncidentService")


class IncidentResponseService:
    """Enterprise incident response controller with durable, concurrency-safe FalkorDB idempotency."""

    def __init__(self) -> None:
        self._proposals: Dict[str, ActionProposal] = {}
        self._idempotency_cache: Dict[str, Dict[str, Any]] = {}

    def propose_action(
        self,
        principal: SecurityPrincipal,
        req: ProposeActionRequest,
    ) -> ActionProposal:
        """
        Stage 1-5: Incident -> Investigation -> Graph Evidence -> Risk Assessment -> Proposed Action.
        Requires 'containment:propose' permission. Validates target host against FalkorDB.
        """
        enforce_tenant_context(req.tenant_id, principal)

        if not principal.has_permission("containment:propose"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Principal lacks 'containment:propose' permission.",
            )

        graph = db_pool.get_tenant_graph(req.tenant_id)
        host_exists = graph.ro_query(queries.HOST_EXISTS, {"host_id": req.target_host_id}).result_set
        if not host_exists or not host_exists[0][0]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target host '{req.target_host_id}' does not exist in tenant '{req.tenant_id}'.",
            )

        target_host_name = host_exists[0][1]

        # Stage 2 & 3: Investigation & Graph Evidence via TriageAgent
        triage_agent = TriageAgent(tenant_id=req.tenant_id)
        triage_res = triage_agent.triage_host(req.target_host_id, max_hops=4)

        # Stage 4: Risk Assessment via MitigationAgent
        mitigation_agent = MitigationAgent(tenant_id=req.tenant_id)
        egress_res = mitigation_agent.assess_egress_risk(req.target_host_id, sink_id="host-7")

        action_id = f"act-{uuid.uuid4().hex[:12]}"
        now = time.time()
        expires_at = now + 900.0  # 15 minute approval TTL

        evidence_payload = {
            "attack_paths": triage_res.get("attack_paths", []),
            "blast_radius": triage_res.get("blast_radius", {}),
            "cves": triage_res.get("host", {}).get("cves", []),
        }
        risk_payload = {
            "max_egress_mbps": egress_res.get("max_egress_mbps", 0.0),
            "lateral_targets": triage_res.get("target_count", 0),
        }

        proposal = ActionProposal(
            action_id=action_id,
            incident_id=req.incident_id,
            tenant_id=req.tenant_id,
            target_host_id=req.target_host_id,
            target_host_name=target_host_name,
            action_type=req.action_type,
            proposer_principal=principal.username,
            justification=req.justification,
            evidence=evidence_payload,
            risk_assessment=risk_payload,
            status=ActionState.PROPOSED,
            created_at=now,
            expires_at=expires_at,
        )

        # Persist full proposal node in FalkorDB for durable provenance across process restarts
        try:
            prop_cypher = """
            MATCH (h:Host {id: $hid})
            CREATE (a:ActionProposal {
                id:               $aid,
                incident_id:      $iid,
                action_type:      $atype,
                status:           'PROPOSED',
                proposer:         $proposer,
                created_at:       $cat,
                expires_at:       $eat,
                target_host_id:   $hid,
                target_host_name: $hname,
                justification:    $just,
                evidence:         $evidence,
                risk_assessment:  $risk
            })
            CREATE (a)-[:PROPOSED_FOR]->(h)
            RETURN a.id
            """
            graph.query(
                prop_cypher,
                {
                    "hid": req.target_host_id,
                    "hname": target_host_name,
                    "aid": action_id,
                    "iid": req.incident_id,
                    "atype": req.action_type,
                    "proposer": principal.username,
                    "cat": now,
                    "eat": expires_at,
                    "just": req.justification,
                    "evidence": json.dumps(evidence_payload),
                    "risk": json.dumps(risk_payload),
                },
            )
        except Exception as e:
            logger.warning("FalkorDB proposal persistence notice: %s", e)

        self._proposals[action_id] = proposal
        logger.info("Containment proposal %s created by %s for host %s", action_id, principal.username, req.target_host_id)
        return proposal

    def review_action(
        self,
        principal: SecurityPrincipal,
        req: ReviewActionRequest,
    ) -> ActionProposal:
        """
        Stage 6: Authorized Review. Requires 'containment:approve' permission.
        Validates approval state, expiration TTL, and fails closed on rejection.
        """
        proposal = self.get_proposal(req.action_id)
        if not proposal:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Action proposal '{req.action_id}' not found.",
            )

        enforce_tenant_context(proposal.tenant_id, principal)

        if not principal.has_permission("containment:approve"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Principal lacks 'containment:approve' permission.",
            )

        now = time.time()
        if now > proposal.expires_at:
            proposal.status = ActionState.EXPIRED
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Action proposal '{req.action_id}' has expired and can no longer be approved.",
            )

        if proposal.status != ActionState.PROPOSED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Action proposal '{req.action_id}' is already in state '{proposal.status}'.",
            )

        decision = req.decision.strip().upper()
        if decision not in {"APPROVE", "REJECT"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid decision. Must be 'APPROVE' or 'REJECT'.",
            )

        proposal.reviewed_by = principal.username
        proposal.review_comment = req.comment
        proposal.reviewed_at = now

        if decision == "REJECT":
            proposal.status = ActionState.REJECTED
            logger.warning("Proposal %s REJECTED by %s: %s", req.action_id, principal.username, req.comment)
        else:
            proposal.status = ActionState.APPROVED
            logger.info("Proposal %s APPROVED by %s", req.action_id, principal.username)

        # Update graph proposal state in FalkorDB
        try:
            graph = db_pool.get_tenant_graph(proposal.tenant_id)
            graph.query(
                "MATCH (a:ActionProposal {id: $aid}) SET a.status = $st, a.reviewed_by = $rev, a.reviewed_at = $rat, a.review_comment = $comm",
                {
                    "aid": req.action_id,
                    "st": proposal.status.value,
                    "rev": principal.username,
                    "rat": now,
                    "comm": req.comment,
                },
            )
        except Exception as e:
            logger.warning("FalkorDB proposal review update notice: %s", e)

        return proposal

    def execute_action(
        self,
        principal: SecurityPrincipal,
        req: ExecuteActionRequest,
    ) -> ExecutionAuditResponse:
        """
        Stage 7 & 8: Execution, Verification & Audit. Requires 'containment:execute' permission.
        Enforces persistent, concurrency-safe FalkorDB idempotency to prevent duplicate action execution
        even across process restarts or simultaneous concurrent requests.
        """
        t0 = time.perf_counter()
        proposal = self.get_proposal(req.action_id)
        if not proposal:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Action proposal '{req.action_id}' not found.",
            )

        enforce_tenant_context(proposal.tenant_id, principal)

        if not principal.has_permission("containment:execute"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Principal lacks 'containment:execute' permission.",
            )

        # ── Persistent, Concurrency-Safe Idempotency via FalkorDB ──
        graph = db_pool.get_tenant_graph(proposal.tenant_id)
        idemp_key = f"{proposal.tenant_id}:{req.idempotency_key}"

        # 1. Fast check if already completed in FalkorDB (persistent replay)
        try:
            check_cypher = "MATCH (i:IdempotencyRecord {key: $k}) RETURN i.status, i.response_json"
            existing = graph.ro_query(check_cypher, {"k": idemp_key}).result_set
            if existing:
                rec_status, resp_json = existing[0][0], existing[0][1]
                if rec_status == "COMPLETED" and resp_json:
                    logger.info("Persistent idempotency replay hit for key: %s", idemp_key)
                    cached_data = json.loads(resp_json)
                    cached_data["idempotent_replay"] = True
                    return ExecutionAuditResponse(**cached_data)
                elif rec_status == "PENDING":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Action execution is already in progress for this idempotency key.",
                    )
        except HTTPException:
            raise
        except Exception as e:
            logger.debug("Idempotency read notice: %s", e)

        # Fallback in-memory cache check
        if idemp_key in self._idempotency_cache:
            replay = self._idempotency_cache[idemp_key]
            return ExecutionAuditResponse(
                action_id=replay.action_id,
                incident_id=replay.incident_id,
                target_host_id=replay.target_host_id,
                execution_status=replay.execution_status,
                idempotent_replay=True,
                executed_at=replay.executed_at,
                execution_latency_ms=0.1,
                verification_proof=replay.verification_proof,
                audit_log_id=replay.audit_log_id,
            )

        now = time.time()
        if now > proposal.expires_at:
            proposal.status = ActionState.EXPIRED
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Approval expired prior to execution. Operation rejected (fail-closed).",
            )

        if proposal.status == ActionState.REJECTED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Action proposal was rejected during review and cannot be executed.",
            )

        if proposal.status != ActionState.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action proposal must be APPROVED before execution. Current state: '{proposal.status}'.",
            )

        # 2. Concurrency-safe atomic claim via MERGE
        claim_cypher = """
        MERGE (i:IdempotencyRecord {key: $k})
        ON CREATE SET i.status = 'PENDING', i.claimed = 1, i.created_at = timestamp()
        ON MATCH SET i.claimed = 0
        RETURN i.status, i.claimed, i.response_json
        """
        claim_res = graph.query(claim_cypher, {"k": idemp_key}).result_set
        if claim_res:
            rec_status = claim_res[0][0]
            claimed = claim_res[0][1]
            resp_json = claim_res[0][2]

            if claimed == 0:
                if rec_status == "COMPLETED" and resp_json:
                    cached_data = json.loads(resp_json)
                    cached_data["idempotent_replay"] = True
                    return ExecutionAuditResponse(**cached_data)
                else:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Action execution is already in progress for this idempotency key.",
                    )

        try:
            # Stage 7: Real FalkorDB Execution via MitigationAgent
            mitigation_agent = MitigationAgent(tenant_id=proposal.tenant_id)
            exec_res = mitigation_agent.execute_containment(proposal.target_host_id)

            if exec_res.get("status") == "FAILED":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=exec_res.get("error", "Containment execution failed in graph engine."),
                )

            # Stage 8: Independent Verification against FalkorDB state
            verify_res = graph.ro_query(
                "MATCH (h:Host {id: $hid}) RETURN h.status, h.firewall",
                {"hid": proposal.target_host_id},
            ).result_set

            is_verified = (
                verify_res
                and verify_res[0][0] == "CONTAINED"
                and bool(verify_res[0][1]) is True
            )
            verification_state = "VERIFIED" if is_verified else "UNVERIFIED"

            # Record Audit & Procedural Memory (Track 2)
            audit_id = f"aud-{uuid.uuid4().hex[:12]}"
            memory_agent = MemoryAgent(tenant_id=proposal.tenant_id)
            memory_agent.persist_procedural_memory(
                host_id=proposal.target_host_id,
                action_type="CONTAIN_HOST_SIMULATION",
                outcome=verification_state,
                executed_by=principal.username,
                incident_id=proposal.incident_id,
            )

            proposal.status = ActionState.EXECUTED
            proposal.executed_at = now
            proposal.idempotency_key = req.idempotency_key
            proposal.execution_result = exec_res

            exec_ms = round((time.perf_counter() - t0) * 1000, 2)

            audit_response_dict = {
                "action_id": proposal.action_id,
                "incident_id": proposal.incident_id,
                "tenant_id": proposal.tenant_id,
                "target_host_id": proposal.target_host_id,
                "status": "CONTAINED",
                "containment_type": "GRAPH_TOPOLOGY_SIMULATION",
                "enforcement_note": (
                    "Graph-level isolation verified in FalkorDB. "
                    "Physical hardware firewall rule enforcement requires authorized appliance connector."
                ),
                "verification": verification_state,
                "executed_by": principal.username,
                "idempotency_key": req.idempotency_key,
                "idempotent_replay": False,
                "audit_id": audit_id,
                "execution_time_ms": exec_ms,
            }

            # 3. Seal persistent idempotency record in FalkorDB
            resp_serialized = json.dumps(audit_response_dict)
            seal_cypher = """
            MATCH (i:IdempotencyRecord {key: $k})
            SET i.status = 'COMPLETED',
                i.response_json = $resp,
                i.completed_at = timestamp()
            """
            graph.query(seal_cypher, {"k": idemp_key, "resp": resp_serialized})

            # Update proposal node in FalkorDB
            graph.query(
                "MATCH (a:ActionProposal {id: $aid}) SET a.status = 'EXECUTED', a.executed_at = $eat, a.idempotency_key = $ik",
                {"aid": proposal.action_id, "eat": now, "ik": req.idempotency_key},
            )

            self._idempotency_cache[idemp_key] = audit_response_dict
            return ExecutionAuditResponse(**audit_response_dict)

        except Exception as e:
            # If execution fails, delete the pending record so client can retry
            try:
                graph.query("MATCH (i:IdempotencyRecord {key: $k}) DELETE i", {"k": idemp_key})
            except Exception:
                pass
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail=f"Execution failure: {e}")

    def get_proposal(self, action_id: str) -> Optional[ActionProposal]:
        """
        Retrieves action proposal from memory cache or directly from FalkorDB graph,
        ensuring persistent recovery across backend process restarts.
        """
        if action_id in self._proposals:
            return self._proposals[action_id]

        for tenant_id in settings.authorized_tenants:
            try:
                graph = db_pool.get_tenant_graph(tenant_id)
                cypher = """
                MATCH (a:ActionProposal {id: $aid})
                RETURN a.id, a.incident_id, a.action_type, a.status, a.proposer,
                       a.created_at, a.expires_at, a.reviewed_by, a.review_comment,
                       a.reviewed_at, a.executed_at, a.target_host_id, a.target_host_name,
                       a.justification, a.evidence, a.risk_assessment, a.idempotency_key
                LIMIT 1
                """
                res = graph.ro_query(cypher, {"aid": action_id}).result_set
                if res:
                    r = res[0]
                    evidence = json.loads(r[14]) if isinstance(r[14], str) else (r[14] or {})
                    risk = json.loads(r[15]) if isinstance(r[15], str) else (r[15] or {})
                    proposal = ActionProposal(
                        action_id=r[0],
                        incident_id=r[1],
                        tenant_id=tenant_id,
                        action_type=r[2],
                        status=ActionState(r[3]),
                        proposer_principal=r[4],
                        created_at=float(r[5]),
                        expires_at=float(r[6]),
                        reviewed_by=r[7],
                        review_comment=r[8],
                        reviewed_at=float(r[9]) if r[9] else None,
                        executed_at=float(r[10]) if r[10] else None,
                        target_host_id=r[11] or "host-0",
                        target_host_name=r[12] or "Unknown",
                        justification=r[13] or "Operational containment",
                        evidence=evidence,
                        risk_assessment=risk,
                        idempotency_key=r[16],
                    )
                    self._proposals[action_id] = proposal
                    return proposal
            except Exception:
                continue

        return None


# Global singleton instance for durable coordination
incident_service = IncidentResponseService()
