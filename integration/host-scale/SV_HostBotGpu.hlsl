// Fixed shader source, compiled offline by prepare-host-bot-gpu.py.
struct Node { float3 position; uint firstEdge; uint edgeCount; uint flags; };
struct Edge { uint destination; float cost; uint flags; };
struct Request { uint slot; uint generation; uint tick; uint startNode; uint goalNode; uint blockedFlags; };
struct Result { uint slot; uint generation; uint tick; uint graphVersion; uint firstHop; uint status; float cost; uint expansions; };
cbuffer Parameters : register(b0) { uint nodeCount, edgeCount, requestCount, graphVersion, maxExpansions; float lookAheadCost; };
StructuredBuffer<Node> nodes : register(t0);
StructuredBuffer<Edge> edges : register(t1);
StructuredBuffer<Request> requests : register(t2);
RWStructuredBuffer<Result> results : register(u0);
groupshared float distances[2048];
groupshared uint firstHops[2048];
groupshared uint closed[2048];
groupshared float bestCost[64];
groupshared uint bestNode[64];
groupshared uint current, finished, iterations;
[numthreads(64,1,1)]
void main(uint3 group : SV_GroupID, uint lane : SV_GroupIndex)
{
    if (group.x >= requestCount) return;
    Request req = requests[group.x];
    for (uint n = lane; n < nodeCount; n += 64) {
        distances[n] = n == req.startNode ? 0.0f : 3.402823466e+38f;
        firstHops[n] = 0xffffffff; closed[n] = 0;
    }
    if (lane == 0) { finished = 0; iterations = 0; current = 0xffffffff; }
    GroupMemoryBarrierWithGroupSync();
    bool valid = req.startNode < nodeCount && req.goalNode < nodeCount;
    if (valid && ((nodes[req.startNode].flags | nodes[req.goalNode].flags) & req.blockedFlags)) valid = false;
    if (valid) {
        for (uint iteration = 0; iteration < maxExpansions; ++iteration) {
            float cost = 3.402823466e+38f; uint candidate = 0xffffffff;
            for (uint n = lane; n < nodeCount; n += 64)
                if (!closed[n] && (distances[n] < cost || (distances[n] == cost && n < candidate))) {
                    cost = distances[n]; candidate = n;
                }
            bestCost[lane] = cost; bestNode[lane] = candidate;
            GroupMemoryBarrierWithGroupSync();
            for (uint width = 32; width > 0; width >>= 1) {
                if (lane < width && (bestCost[lane+width] < bestCost[lane] ||
                    (bestCost[lane+width] == bestCost[lane] && bestNode[lane+width] < bestNode[lane]))) {
                    bestCost[lane] = bestCost[lane+width]; bestNode[lane] = bestNode[lane+width];
                }
                GroupMemoryBarrierWithGroupSync();
            }
            if (lane == 0) {
                current = bestCost[0] < 3.402823466e+38f ? bestNode[0] : 0xffffffff;
                iterations = iteration + 1;
                if (current == 0xffffffff) finished = 2;
                else if (current == req.goalNode) finished = 1;
                else closed[current] = 1;
            }
            GroupMemoryBarrierWithGroupSync();
            if (finished != 0) break;
            // Each lane owns destinations, preventing races for duplicate edges.
            Node source = nodes[current];
            for (uint destination = lane; destination < nodeCount; destination += 64) {
                if (closed[destination] || (nodes[destination].flags & req.blockedFlags)) continue;
                float updated = distances[destination];
                for (uint e = source.firstEdge; e < source.firstEdge + source.edgeCount; ++e) {
                    Edge edge = edges[e];
                    if (edge.destination == destination && !(edge.flags & req.blockedFlags))
                        updated = min(updated, distances[current] + edge.cost);
                }
                if (updated < distances[destination]) {
                    distances[destination] = updated;
                    firstHops[destination] = current == req.startNode || distances[current] < lookAheadCost
                        ? destination : firstHops[current];
                }
            }
            GroupMemoryBarrierWithGroupSync();
        }
    }
    if (lane == 0) {
        Result result;
        result.slot = req.slot; result.generation = req.generation; result.tick = req.tick;
        result.graphVersion = graphVersion; result.status = valid ? (finished == 0 ? 3 : finished) : 4;
        result.firstHop = finished == 1 ? (req.startNode == req.goalNode ? req.startNode : firstHops[req.goalNode]) : 0xffffffff;
        result.cost = finished == 1 ? distances[req.goalNode] : 0.0f;
        result.expansions = iterations; results[group.x] = result;
    }
}
