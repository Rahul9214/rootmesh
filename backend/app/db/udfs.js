// RootMesh — Monte Carlo Blast-Radius UDF
// Registered in FalkorDB via db.udf_load
// Language: JavaScript (FalkorDB v6 UDF API)

function blast_radius(start_node_id, runs) {
  var infectedCounts = {};
  var it = graph.iterateNodes('Host');
  var startNode = null;
  var step = it.next();
  while (!step.done) {
    if (step.value.attributes && step.value.attributes.id === start_node_id) {
      startNode = step.value;
      break;
    }
    step = it.next();
  }
  if (!startNode) {
    return JSON.stringify({ error: "Host node not found", start_node_id: start_node_id });
  }

  var numRuns = parseInt(runs, 10) || 100;
  for (var r = 0; r < numRuns; r++) {
    var frontier = [startNode];
    var visited = {};
    visited[startNode.id] = true;

    while (frontier.length > 0) {
      var curr = frontier.shift();
      var trav = graph.traverse([curr], { direction: 'outgoing' });
      if (trav && trav.length > 0) {
        var neighbors = trav[0];
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
