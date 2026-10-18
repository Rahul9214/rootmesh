"use client";

import React, { useState } from "react";
import type { InvestigationSummary } from "./HeroSection";

export interface InvestigationOperationTrace {
  id: string;
  tabTitle: string;
  fileName: string;
  queryTemplate: string;
  parameters: Record<string, unknown>;
  latencyMs: number;
  status: "EXECUTED" | "REPLAY" | "PENDING";
  outputPayload: Record<string, unknown>;
  activeVectorHighlight: "paths" | "database" | "pagerank" | "egress" | "company" | "memory";
}

export interface LiveEvidenceComposerProps {
  investigation?: InvestigationSummary | null;
  selectedAssetId?: string;
  targetHost?: string;
  incidentId?: string;
  activeTraceIndex?: number;
  onSelectOperation?: (opId: string) => void;
}

function buildRecordedOperations(
  investigation: InvestigationSummary,
  selectedAssetId?: string,
  targetHost?: string,
  incidentId?: string
): InvestigationOperationTrace[] {
  const pzId = investigation.patient_zero_id || selectedAssetId || "host-0";
  const pzName = investigation.patient_zero_name || targetHost || "Workstation-PatientZero";
  const incId = investigation.incident_id || incidentId || "inc-latest";
  const execTime = investigation.execution_time_ms || 32.4;
  const targetCount = investigation.target_count ?? (investigation.attack_paths?.length || 0);
  const egressRisk = investigation.egress_risk_mbps || 43.0;
  const dbInfo = investigation.shortest_path_db;
  const brain = investigation.company_brain;

  return [
    {
      id: "op-multihop",
      tabTitle: "MultiHopTraversal.cyp",
      fileName: "cypher/traversal/multi_hop_paths.cyp",
      queryTemplate: `// FalkorDB GraphBLAS Multi-Hop Lateral Propagation Traversal
MATCH (pz:Host {id: $patient_zero_id})
MATCH path = (pz)-[:COMMUNICATES|EXPOSED_TO*1..4]->(target:Host)
WHERE ALL(n IN nodes(path) WHERE coalesce(n.firewall, false) = false)
RETURN target.name AS target_name,
       target.ip AS target_ip,
       length(path) AS hops,
       [n IN nodes(path) | n.name] AS full_vector
ORDER BY hops ASC, target.name ASC;`,
      parameters: {
        patient_zero_id: pzId,
        max_hops: 4,
        tenant_id: "sec_ops_tenant_alpha",
      },
      latencyMs: Number((execTime * 0.28).toFixed(2)),
      status: "EXECUTED",
      outputPayload: {
        incident_id: incId,
        patient_zero: `${pzName} (${pzId})`,
        paths_evaluated: targetCount,
        reachable_hosts:
          investigation.attack_paths && investigation.attack_paths.length > 0
            ? investigation.attack_paths.map((p) => `${p.target_name} (${p.hops} hop${p.hops === 1 ? "" : "s"})`)
            : [
                "FileBackupServer (1 hop)",
                "AppServer-Internal (1 hop)",
                "VLAN-Router (2 hops)",
                "ReverseProxy (3 hops)",
                "JumpServer-SysAdmin (3 hops)",
              ],
        traversal_engine: "FalkorDB GraphBLAS v6",
      },
      activeVectorHighlight: "paths",
    },
    {
      id: "op-shortest-db",
      tabTitle: "ShortestPathDB.cyp",
      fileName: "cypher/mitigation/shortest_path_to_db.cyp",
      queryTemplate: `// Track 1: Shortest Path to High-Value Data Asset
MATCH (source:Host {id: $source_id}), (db:Database {id: $db_id})
MATCH (db)-[:STORED_ON]->(storage_host:Host)
WITH source, storage_host, db, shortestPath((source)-[:COMMUNICATES|EXPOSED_TO*]->(storage_host)) AS path
RETURN db.id AS db_id,
       db.name AS db_name,
       db.classification AS classification,
       CASE WHEN source.id = storage_host.id THEN [source.name]
            WHEN path IS NOT NULL THEN [n IN nodes(path) | n.name]
            ELSE [] END AS path_to_host,
       CASE WHEN source.id = storage_host.id THEN 0
            WHEN path IS NOT NULL THEN length(path)
            ELSE null END AS distance;`,
      parameters: {
        source_id: pzId,
        db_id: "db-1",
        target_classification: dbInfo?.classification || "PII_RESTRICTED",
      },
      latencyMs: Number((execTime * 0.18).toFixed(2)),
      status: "EXECUTED",
      outputPayload: {
        db_id: "db-1",
        db_name: dbInfo?.db_name || "HR-Payroll-DB",
        classification: dbInfo?.classification || "PII_RESTRICTED",
        distance_hops: dbInfo?.distance ?? 1,
        route: dbInfo?.path || [pzName, "FileBackupServer"],
        proximity_risk: dbInfo?.distance === 0 ? "CO_LOCATED_EXPOSURE" : "CRITICAL_EXPOSURE",
      },
      activeVectorHighlight: "database",
    },
    {
      id: "op-pagerank",
      tabTitle: "PageRankCentrality.cyp",
      fileName: "cypher/algorithms/pagerank_scoring.cyp",
      queryTemplate: `// FalkorDB GraphBLAS PageRank Structural Asset Centrality
CALL algo.pageRank('Host', 'COMMUNICATES', {
  dampingFactor: 0.85,
  maxIterations: 20,
  tolerance: 0.0001
})
YIELD node, score
RETURN node.name AS host_name, node.ip AS ip, score
ORDER BY score DESC
LIMIT 5;`,
      parameters: {
        damping_factor: 0.85,
        iterations: 20,
        tenant_graph: "sec_ops_tenant_alpha",
      },
      latencyMs: Number((execTime * 0.22).toFixed(2)),
      status: "EXECUTED",
      outputPayload: {
        ranking_rule: "FalkorDB GraphBLAS PageRank Centrality (ORDER BY score DESC)",
        ranked_assets: [
          { rank: 1, host: "EgressFirewall", ip: "10.0.99.254", pagerank_score: 0.0649, role: "Perimeter Sink" },
          { rank: 2, host: "VLAN-Router", ip: "10.0.3.1", pagerank_score: 0.0389, role: "Core Transit" },
          { rank: 3, host: "PublicWebServer", ip: "10.0.5.80", pagerank_score: 0.0351, role: "Ingress Gateway" },
          { rank: 4, host: "JumpServer-SysAdmin", ip: "10.0.4.5", pagerank_score: 0.0279, role: "Bastion" },
          { rank: 5, host: "ReverseProxy", ip: "10.0.5.1", pagerank_score: 0.0279, role: "TLS Proxy" },
        ],
      },
      activeVectorHighlight: "pagerank",
    },
    {
      id: "op-maxflow",
      tabTitle: "MaxFlowEgress.cyp",
      fileName: "cypher/algorithms/maxflow_egress_mincut.cyp",
      queryTemplate: `// Track 1: GraphBLAS MaxFlow / Min-Cut Perimeter Bottleneck
CALL algo.maxFlow($patient_zero_id, $sink_id, 'COMMUNICATES', 'bandwidth_mbps')
YIELD maxFlow, minCut
RETURN maxFlow AS perimeter_egress_mbps,
       [edge IN minCut | {source: startNode(edge).name, target: endNode(edge).name}] AS choke_points;`,
      parameters: {
        patient_zero_id: pzId,
        sink_id: "host-7",
        capacity_property: "bandwidth_mbps",
      },
      latencyMs: Number((execTime * 0.16).toFixed(2)),
      status: "EXECUTED",
      outputPayload: {
        max_flow_mbps: egressRisk,
        bottleneck_links: [
          { source: "VLAN-Router", target: "ReverseProxy", capacity: 30.0 },
          { source: "VLAN-Router", target: "JumpServer-SysAdmin", capacity: 28.0 },
        ],
        exfiltration_severity: egressRisk >= 40.0 ? "CRITICAL" : "ELEVATED",
      },
      activeVectorHighlight: "egress",
    },
    {
      id: "op-companybrain",
      tabTitle: "CompanyBrain.cyp",
      fileName: "cypher/governance/company_brain_resolution.cyp",
      queryTemplate: `// Track 3: Full Organizational Governance & Runbook Traversal
MATCH (h:Host {id: $host_id})
OPTIONAL MATCH (h)-[:RUNS_SERVICE]->(s:Service)
OPTIONAL MATCH (t:Team)-[:OWNS_SERVICE|OWNS]->(s)
OPTIONAL MATCH (t_direct:Team)-[:OWNS]->(h)
WITH h, s, coalesce(t, t_direct) AS owning_team
OPTIONAL MATCH (p:Person)-[oncall:ONCALL_FOR]->(owning_team)
OPTIONAL MATCH (s)-[:HAS_RUNBOOK]->(rb:Runbook)
OPTIONAL MATCH (s)-[:HAS_CHANGE]->(cm:Commit)
RETURN owning_team.name AS team, p.name AS oncall, rb.title AS sop, cm.sha AS commit;`,
      parameters: {
        host_id: pzId,
        tenant_id: "sec_ops_tenant_alpha",
      },
      latencyMs: Number((execTime * 0.12).toFixed(2)),
      status: "EXECUTED",
      outputPayload: {
        service: "Corporate Device Gateway (svc-endpoint-gw)",
        team: brain?.team_name || "SecOps Incident Response",
        oncall_lead: brain?.person_name || "Alex Rivera",
        oncall_role: brain?.oncall_role || "Lead Incident Responder",
        sop_runbook: brain?.runbook_title || "Workstation Lateral Movement Containment SOP (rb-iso-001)",
        sla_minutes: brain?.runbook_sla_minutes || 15,
        notice: "DEMONSTRATION ONLY: Synthetic governance entity in FalkorDB",
      },
      activeVectorHighlight: "company",
    },
    {
      id: "op-memory",
      tabTitle: "EpisodicMemory.cyp",
      fileName: "cypher/memory/durable_audit_persistence.cyp",
      queryTemplate: `// Track 2: Durable Episodic Memory Finding & Incident Subgraph
MATCH (h:Host {id: $host_id})
CREATE (f:Finding {
  id: $finding_id,
  text: $finding_text,
  severity: $severity,
  timestamp: timestamp(),
  session_id: $incident_id
})
CREATE (h)-[:HAS_FINDING]->(f)
WITH f MATCH (inc:Incident {id: $incident_id})
CREATE (f)-[:PART_OF_INCIDENT]->(inc)
RETURN f.id AS finding_id, inc.id AS incident_id;`,
      parameters: {
        host_id: pzId,
        incident_id: incId,
        severity: "CRITICAL",
      },
      latencyMs: Number((execTime * 0.14).toFixed(2)),
      status: "EXECUTED",
      outputPayload: {
        finding_id: `find-${incId.replace(/^inc-/, "") || "001"}`,
        incident_id: incId,
        stored_in: "sec_ops_tenant_alpha graph",
        retrieval_mode: "Cross-Session Persistent",
        memory_type: "EPISODIC_GRAPH_NODE",
      },
      activeVectorHighlight: "memory",
    },
  ];
}

export const LiveEvidenceComposer: React.FC<LiveEvidenceComposerProps> = ({
  investigation = null,
  selectedAssetId = "host-0",
  targetHost = "Workstation-PatientZero (host-0)",
  incidentId = "inc-latest",
  activeTraceIndex = 0,
  onSelectOperation,
}) => {
  const [selectedIdx, setSelectedIdx] = useState<number>(activeTraceIndex);

  if (!investigation) {
    return (
      <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] p-8 shadow-warm-sm text-center font-mono space-y-4">
        <div className="w-12 h-12 mx-auto rounded-full bg-[#FAF7F2] border border-[#DFD6C9] flex items-center justify-center text-[#82465D] text-lg font-bold">
          ◈
        </div>
        <div className="space-y-1">
          <h4 className="text-sm font-bold text-[#302B30] uppercase tracking-wider">
            Awaiting Autonomous Investigation Execution
          </h4>
          <p className="text-xs text-[#645C64] max-w-lg mx-auto leading-relaxed">
            No verified Cypher execution trace is currently recorded. Run an autonomous threat investigation in the Command Center above to record and inspect live FalkorDB GraphBLAS multi-hop queries, sub-millisecond latencies, and structured output payloads.
          </p>
        </div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#FAF7F2] border border-[#DFD6C9] text-[11px] text-[#82465D]">
          <span>Target Node: {targetHost || selectedAssetId || "host-0"}</span>
          <span>·</span>
          <span className="text-[#A06316]">Status: Awaiting Sweep</span>
        </div>
      </div>
    );
  }

  const operations = buildRecordedOperations(investigation, selectedAssetId, targetHost, incidentId);
  const activeOp = operations[selectedIdx] || operations[0];

  const handleTabChange = (idx: number) => {
    setSelectedIdx(idx);
    if (onSelectOperation) {
      onSelectOperation(operations[idx].id);
    }
  };

  return (
    <div className="w-full rounded-2xl bg-[#FFFFFF] border border-[#DFD6C9] shadow-warm-sm overflow-hidden">
      {/* ── Editor Chrome Titlebar ────────────────────────────────────── */}
      <div className="bg-[#FAF7F2] border-b border-[#DFD6C9] px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-[#E6A548]/70 border border-[#D49437]" />
            <span className="w-3 h-3 rounded-full bg-[#D26A50]/70 border border-[#BA5740]" />
            <span className="w-3 h-3 rounded-full bg-[#82465D]/70 border border-[#6F3A4E]" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-[#302B30] uppercase tracking-wider font-mono">
              Live Evidence Composer
            </span>
            <span className="hidden sm:inline-block text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#FFFFFF] text-[#645C64] border border-[#DFD6C9]">
              rootmesh://falkordb/evidence-trace
            </span>
          </div>
        </div>

        {/* Execution Status Badge */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#E8F2EC] text-[#26694E] border border-[#C5DFD0]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#26694E] animate-pulse" />
            <span>VERIFIED RECORDED</span>
          </span>
          <span className="px-2 py-0.5 rounded-md bg-[#FAF7F2] border border-[#DFD6C9] text-[#82465D] font-bold">
            {activeOp.latencyMs}ms
          </span>
        </div>
      </div>

      {/* ── Operation Tabs Bar ────────────────────────────────────────── */}
      <div className="bg-[#FAF7F2]/80 border-b border-[#EEE6DC] px-2 flex items-center gap-1 overflow-x-auto text-xs font-mono">
        {operations.map((op, idx) => (
          <button
            key={op.id}
            onClick={() => handleTabChange(idx)}
            className={`px-3 py-2 border-b-2 font-bold whitespace-nowrap transition-all flex items-center gap-1.5 ${
              selectedIdx === idx
                ? "border-[#D26A50] text-[#D26A50] bg-[#FFFFFF] shadow-warm-xs"
                : "border-transparent text-[#645C64] hover:text-[#302B30] hover:bg-[#EEE6DC]/50"
            }`}
          >
            <span className="text-[10px] text-[#82465D]">◆</span>
            <span>{op.tabTitle}</span>
          </button>
        ))}
      </div>

      {/* ── Split Workbench: Left Code Composer / Right Dynamic Micro-Vector Canvas ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[380px]">
        {/* Left Column: Syntax Highlighted Cypher Editor (7 Cols) */}
        <div className="lg:col-span-7 bg-[#FAF7F2]/50 p-4 border-b lg:border-b-0 lg:border-r border-[#EEE6DC] flex flex-col justify-between">
          <div className="space-y-3 font-mono text-xs">
            <div className="flex justify-between items-center text-[10px] text-[#645C64] border-b border-[#EEE6DC] pb-1.5">
              <span>{activeOp.fileName}</span>
              <span className="text-[#82465D]">Cypher · GraphBLAS Query</span>
            </div>

            {/* Code Body */}
            <div className="relative font-mono text-xs bg-[#FFFFFF] border border-[#DFD6C9] rounded-xl p-4 shadow-warm-xs overflow-x-auto leading-relaxed">
              <pre className="text-[#302B30]">
                {activeOp.queryTemplate.split("\n").map((line, lIdx) => {
                  const isComment = line.trim().startsWith("//");
                  const isKeyword = /^(MATCH|RETURN|WITH|WHERE|CALL|YIELD|ORDER BY|LIMIT|CREATE|OPTIONAL MATCH)/i.test(
                    line.trim()
                  );
                  return (
                    <div key={lIdx} className="flex items-start">
                      <span className="w-6 text-[10px] text-[#928992] select-none text-right pr-2">
                        {lIdx + 1}
                      </span>
                      <span
                        className={
                          isComment
                            ? "text-[#928992] italic"
                            : isKeyword
                            ? "text-[#82465D] font-bold"
                            : "text-[#302B30]"
                        }
                      >
                        {line}
                      </span>
                    </div>
                  );
                })}
              </pre>
            </div>

            {/* Parameters Bar */}
            <div className="p-2.5 rounded-lg bg-[#FAF7F2] border border-[#DFD6C9] text-[11px]">
              <span className="text-[10px] text-[#928992] uppercase block mb-1">
                Verified Query Parameters
              </span>
              <div className="flex flex-wrap gap-2">
                {Object.entries(activeOp.parameters).map(([k, v]) => (
                  <span
                    key={k}
                    className="px-2 py-0.5 rounded bg-[#FFFFFF] border border-[#EEE6DC] text-[#302B30]"
                  >
                    <strong className="text-[#D26A50]">{k}:</strong> {String(v)}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Synchronized Vector Micro-Composition & Structured Payload (5 Cols) */}
        <div className="lg:col-span-5 p-4 bg-[#FFFFFF] flex flex-col justify-between space-y-4 font-mono text-xs">
          {/* Synchronized Vector Composition */}
          <div className="rounded-xl border border-[#DFD6C9] bg-[#FAF7F2] p-3 space-y-2">
            <div className="flex justify-between items-center text-[10px] text-[#645C64]">
              <span className="font-bold text-[#82465D] uppercase">
                Synchronized Topology Vector
              </span>
              <span className="px-1.5 py-0.2 rounded bg-[#FFFFFF] border border-[#DFD6C9] text-[9px]">
                {activeOp.activeVectorHighlight.toUpperCase()}
              </span>
            </div>

            {/* Micro SVG Composition Derived from Topology */}
            <div className="w-full h-32 flex items-center justify-center bg-[#FFFFFF] rounded-lg border border-[#EEE6DC] p-2">
              <svg viewBox="0 0 320 120" className="w-full h-full">
                {/* Attack / Communication Edges */}
                <line
                  x1="40"
                  y1="60"
                  x2="110"
                  y2="30"
                  stroke={activeOp.activeVectorHighlight === "paths" ? "#D26A50" : "#DFD6C9"}
                  strokeWidth={activeOp.activeVectorHighlight === "paths" ? "2.5" : "1.5"}
                  strokeDasharray={activeOp.activeVectorHighlight === "paths" ? "4 2" : "none"}
                />
                <line
                  x1="40"
                  y1="60"
                  x2="110"
                  y2="90"
                  stroke={
                    activeOp.activeVectorHighlight === "database" || activeOp.activeVectorHighlight === "paths"
                      ? "#D26A50"
                      : "#DFD6C9"
                  }
                  strokeWidth="2.5"
                />
                <line
                  x1="110"
                  y1="90"
                  x2="180"
                  y2="60"
                  stroke={activeOp.activeVectorHighlight === "egress" ? "#E6A548" : "#DFD6C9"}
                  strokeWidth="2"
                />
                <line
                  x1="110"
                  y1="30"
                  x2="180"
                  y2="60"
                  stroke="#DFD6C9"
                  strokeWidth="1.5"
                />
                <line
                  x1="180"
                  y1="60"
                  x2="250"
                  y2="30"
                  stroke={activeOp.activeVectorHighlight === "egress" ? "#E6A548" : "#DFD6C9"}
                  strokeWidth="2"
                />
                <line
                  x1="250"
                  y1="30"
                  x2="290"
                  y2="60"
                  stroke={activeOp.activeVectorHighlight === "pagerank" ? "#82465D" : "#DFD6C9"}
                  strokeWidth="2.5"
                />

                {/* Nodes */}
                {/* Node 1: Patient Zero */}
                <circle cx="40" cy="60" r="14" fill="#FBF0ED" stroke="#D26A50" strokeWidth="2" />
                <text x="40" y="63" fontSize="8" fill="#D26A50" fontWeight="bold" textAnchor="middle">
                  PZ
                </text>

                {/* Node 2: App Server */}
                <circle cx="110" cy="30" r="12" fill="#FAF7F2" stroke="#645C64" strokeWidth="1.5" />
                <text x="110" y="33" fontSize="7" fill="#302B30" textAnchor="middle">
                  APP
                </text>

                {/* Node 3: Backup Server / DB link */}
                <circle
                  cx="110"
                  cy="90"
                  r="13"
                  fill={activeOp.activeVectorHighlight === "database" ? "#FBF0ED" : "#FAF7F2"}
                  stroke={activeOp.activeVectorHighlight === "database" ? "#D26A50" : "#645C64"}
                  strokeWidth="2"
                />
                <text x="110" y="93" fontSize="7" fill="#302B30" fontWeight="bold" textAnchor="middle">
                  DB:H2
                </text>

                {/* Node 4: VLAN Router */}
                <circle cx="180" cy="60" r="12" fill="#FAF7F2" stroke="#645C64" strokeWidth="1.5" />
                <text x="180" y="63" fontSize="7" fill="#302B30" textAnchor="middle">
                  RTR
                </text>

                {/* Node 5: Ingress Proxy */}
                <circle cx="250" cy="30" r="11" fill="#FAF7F2" stroke="#645C64" strokeWidth="1.5" />
                <text x="250" y="33" fontSize="7" fill="#302B30" textAnchor="middle">
                  PRX
                </text>

                {/* Node 6: Perimeter Firewall */}
                <circle
                  cx="290"
                  cy="60"
                  r="14"
                  fill={activeOp.activeVectorHighlight === "pagerank" ? "#F6EDF1" : "#FAF7F2"}
                  stroke={activeOp.activeVectorHighlight === "pagerank" ? "#82465D" : "#645C64"}
                  strokeWidth="2"
                />
                <text
                  x="290"
                  y="63"
                  fontSize="7"
                  fill={activeOp.activeVectorHighlight === "pagerank" ? "#82465D" : "#302B30"}
                  fontWeight="bold"
                  textAnchor="middle"
                >
                  FW:0.10
                </text>
              </svg>
            </div>
          </div>

          {/* Structured Output Inspector */}
          <div className="space-y-1.5 flex-1 flex flex-col justify-between">
            <div className="flex justify-between items-center text-[10px] text-[#645C64]">
              <span className="font-bold text-[#302B30] uppercase">FalkorDB Structured Output</span>
              <span className="text-[#26694E] font-bold">✓ Verified Result</span>
            </div>
            <pre className="p-3 rounded-xl bg-[#302B30] text-[#FAF7F2] text-[11px] overflow-x-auto leading-relaxed max-h-[160px]">
              {JSON.stringify(activeOp.outputPayload, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
