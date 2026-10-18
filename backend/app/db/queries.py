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
