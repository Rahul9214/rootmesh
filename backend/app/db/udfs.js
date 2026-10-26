// RootMesh — Monte Carlo Blast-Radius UDF
// Registered in FalkorDB via db.udf_load
// Language: JavaScript (FalkorDB v6 UDF API)

function blast_radius(start_node, runs) {
  var infectedCounts = {};
  var startNode = null;

  // Resolve starting Host node: direct Node object from Cypher or safe iterator fallback
  if (start_node && typeof start_node === 'object') {
    startNode = start_node;
  } else if (typeof start_node === 'string' && typeof graph !== 'undefined' && typeof graph.iterateNodes === 'function') {
    var it = graph.iterateNodes('Host');
    var step = it.next();
    while (!step.done) {
      if (step.value.attributes && step.value.attributes.id === start_node) {
        startNode = step.value;
        break;
      }
      step = it.next();
    }
  }

  if (!startNode || typeof startNode !== 'object') {
    return JSON.stringify({ error: "Host node not found", start_node: start_node });
  }

  var numRuns = parseInt(runs, 10) || 100;
  for (var r = 0; r < numRuns; r++) {
    var frontier = [startNode];
    var visited = {};
    visited[startNode.id] = true;

    while (frontier.length > 0) {
      var curr = frontier.shift();
      var neighbors = (typeof curr.getNeighbors === 'function')
        ? curr.getNeighbors({ direction: 'outgoing' })
        : ((typeof graph !== 'undefined' && typeof graph.traverse === 'function')
            ? (graph.traverse([curr], { direction: 'outgoing' })[0] || [])
            : []);

      if (neighbors && neighbors.length > 0) {
        for (var j = 0; j < neighbors.length; j++) {
          var neighbor = neighbors[j];
          if (!neighbor || !neighbor.attributes || visited[neighbor.id]) continue;
          if (!neighbor.labels || neighbor.labels.indexOf('Host') === -1) continue;

          // Stochastic WannaCry-style transmission model
          var prob = 0.30;
          if (!neighbor.attributes.firewall)   prob += 0.20;
          if (!neighbor.attributes.smb_signing) prob += 0.15;
          if (!neighbor.attributes.edr)         prob += 0.25;

          if (Math.random() < prob) {
            visited[neighbor.id] = true;
            frontier.push(neighbor);
            var nm = neighbor.attributes.name || neighbor.attributes.id;
            infectedCounts[nm] = (infectedCounts[nm] || 0) + 1;
          }
        }
      }
    }
  }

  return JSON.stringify(infectedCounts);
}

falkor.register("blast_radius", blast_radius);
