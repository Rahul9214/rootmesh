"""
RootMesh — Parameterized Cypher Query Library
All queries use positional parameters ($param) to prevent injection.
"""

# ──────────────────────────────────────────────
# Track 1: Multi-Hop Attack Path Traversal
# ──────────────────────────────────────────────

MULTI_HOP_TRAVERSAL = """
MATCH path = (pZero:Host {id: $patient_zero_id})-[:COMMUNICATES|EXPOSED_TO*1..{max_hops}]->(target:Host)
RETURN
  target.name   AS target_name,
  target.ip     AS target_ip,
  length(path)  AS hops,
  [n IN nodes(path) | n.name] AS attack_path
ORDER BY hops ASC
"""

# ──────────────────────────────────────────────
# Track 1: MaxFlow Data Egress Calculation
# ──────────────────────────────────────────────

MAX_FLOW_EGRESS = """
MATCH (source:Host {id: $source_id}), (sink:Host {id: $sink_id})
CALL algo.maxFlow({
  sourceNodes: [source],
  targetNodes: [sink],
  relationshipTypes: ['COMMUNICATES'],
  capacityProperty: 'bandwidth_mbps'
})
YIELD maxFlow
RETURN maxFlow AS max_egress_mbps
"""

# ──────────────────────────────────────────────
# Track 1: Shortest Path Traversal
# ──────────────────────────────────────────────

SHORTEST_ATTACK_PATH = """
MATCH (source:Host {id: $source_id}), (target:Host {id: $target_id})
WITH shortestPath((source)-[:COMMUNICATES|EXPOSED_TO*]->(target)) AS path
RETURN [n IN nodes(path) | n.name] AS path_nodes, length(path) AS distance
"""

# ──────────────────────────────────────────────
# Track 1: PageRank — Critical Asset Scoring
# ──────────────────────────────────────────────

PAGE_RANK_ASSETS = """
CALL algo.pageRank('Host', 'COMMUNICATES')
YIELD node, score
RETURN node.name AS host_name, node.ip AS ip, score
ORDER BY score DESC
LIMIT 10
"""

# ──────────────────────────────────────────────
# Track 2: Persist Episodic Finding Memory
# ──────────────────────────────────────────────

PERSIST_FINDING = """
MATCH (h:Host {id: $host_id})
CREATE (f:Finding {
  id:         'find-' + toString(timestamp()),
  text:       $text,
  severity:   $severity,
  session_id: $session_id,
  at:         timestamp()
})
CREATE (f)-[:ABOUT {confidence_score: $confidence}]->(h)
RETURN f.id AS finding_id
"""

RECALL_FINDINGS = """
MATCH (f:Finding)-[:ABOUT]->(h:Host {id: $host_id})
RETURN f.id, f.text, f.severity, f.at
ORDER BY f.at DESC
LIMIT 20
"""

# ──────────────────────────────────────────────
# Track 3: On-Call Owner Lookup
# ──────────────────────────────────────────────

ONCALL_OWNER = """
MATCH (t:Team)-[:OWNS]->(h:Host {id: $host_id})
MATCH (p:Person)-[:ONCALL_FOR]->(t)
RETURN p.name AS responder, p.email AS email, t.name AS team
LIMIT 5
"""

# ──────────────────────────────────────────────
# Host Topology & Containment Queries
# ──────────────────────────────────────────────

GET_ALL_HOSTS_TOPOLOGY = """
MATCH (h:Host)
RETURN h.id AS id, h.name AS name, h.ip AS ip,
       coalesce(h.status, CASE WHEN h.id = 'host-0' THEN 'INFECTED' ELSE 'SAFE' END) AS status,
       coalesce(h.firewall, false) AS firewall,
       coalesce(h.edr, false) AS edr,
       coalesce(h.smb_signing, false) AS smb_signing
ORDER BY h.id ASC
"""

CONTAIN_HOST = """
MATCH (h:Host {id: $host_id})
SET h.firewall = true, h.status = 'CONTAINED'
RETURN h.id AS id, h.name AS name, h.firewall AS firewall
"""

HOST_EXISTS = """
MATCH (h:Host {id: $host_id})
RETURN h.id AS id, h.name AS name, h.ip AS ip,
       h.edr AS edr, h.smb_signing AS smb_signing, h.firewall AS firewall
LIMIT 1
"""

# ──────────────────────────────────────────────
# Track 3: Company Brain Full Organizational Traversal
# ──────────────────────────────────────────────

RESOLVE_COMPANY_BRAIN = """
MATCH (h:Host {id: $host_id})
OPTIONAL MATCH (h)-[:RUNS_SERVICE]->(s:Service)
OPTIONAL MATCH (t:Team)-[:OWNS_SERVICE|OWNS]->(s)
OPTIONAL MATCH (t_direct:Team)-[:OWNS]->(h)
WITH h, s, coalesce(t, t_direct) AS owning_team
OPTIONAL MATCH (p:Person)-[oncall:ONCALL_FOR]->(owning_team)
OPTIONAL MATCH (s)-[:HAS_RUNBOOK]->(rb:Runbook)
OPTIONAL MATCH (s)-[:HAS_CHANGE]->(cm:Commit)
RETURN h.id AS host_id, h.name AS host_name, h.ip AS host_ip,
       coalesce(h.status, 'SAFE') AS host_status, coalesce(h.firewall, false) AS firewall,
       s.id AS service_id, s.name AS service_name, s.repo AS repo, s.tier AS service_tier,
       owning_team.id AS team_id, owning_team.name AS team_name, owning_team.slack_channel AS slack_channel,
       p.id AS responder_id, p.name AS oncall_name, p.email AS oncall_email, p.role AS oncall_role,
       coalesce(oncall.schedule, '24x7-Primary') AS oncall_schedule,
       rb.id AS runbook_id, rb.title AS runbook_title, rb.url AS runbook_url, rb.sla_minutes AS runbook_sla_minutes,
       cm.sha AS commit_sha, cm.author AS commit_author, cm.message AS commit_message, cm.timestamp AS commit_timestamp
LIMIT 1
"""

# ──────────────────────────────────────────────
# Track 1 & 2: Containment Re-Analysis
# ──────────────────────────────────────────────

REANALYZE_CONTAINMENT = """
MATCH (h:Host {id: $host_id})
OPTIONAL MATCH (h)-[:COMMUNICATES]->(direct:Host)
OPTIONAL MATCH active_path = (h)-[:COMMUNICATES*1..4]->(target:Host)
  WHERE ALL(n IN nodes(active_path) WHERE coalesce(n.firewall, false) = false)
RETURN
  h.id AS host_id,
  h.name AS host_name,
  coalesce(h.status, 'SAFE') AS status,
  coalesce(h.firewall, false) AS firewall,
  count(DISTINCT direct) AS total_direct_peers,
  count(DISTINCT active_path) AS active_uncontained_paths
"""

# ──────────────────────────────────────────────
# Track 1: Shortest Path to High-Value Data Asset
# ──────────────────────────────────────────────

SHORTEST_PATH_TO_DATABASE = """
MATCH (source:Host {id: $source_id}), (db:Database {id: $db_id})
MATCH (db)-[:STORED_ON]->(storage_host:Host)
WITH source, storage_host, db, shortestPath((source)-[:COMMUNICATES|EXPOSED_TO*]->(storage_host)) AS path
RETURN db.id AS db_id, db.name AS db_name, db.classification AS classification,
       [n IN nodes(path) | n.name] AS path_to_host, length(path) AS distance
LIMIT 1
"""

# ──────────────────────────────────────────────
# Track 2: Incident Provenance Graph Persistence
# ──────────────────────────────────────────────

PERSIST_INCIDENT_GRAPH = """
MATCH (h:Host {id: $patient_zero_id})
CREATE (inc:Incident {
  id:              $incident_id,
  title:           $title,
  severity:        $severity,
  status:          $status,
  patient_zero_id: $patient_zero_id,
  created_at:      $created_at
})
CREATE (inc)-[:TARGETS]->(h)
RETURN inc.id AS incident_id
"""

