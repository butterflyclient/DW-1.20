// Fixed shader source, compiled offline by prepare-host-bot-gpu.py.
struct Node
{
    float3 position;
    uint firstEdge;
    uint edgeCount;
    uint flags;
};
struct Edge
{
    uint destination;
    float cost;
    uint flags;
};
struct Request
{
    uint slot, generation, tick, startNode, goalNode, blockedFlags;
    uint mode, seed;
    float circleX, circleY, circleRadius, minDistance;
    float originX, originY, originZ;
};
struct Result
{
    uint slot;
    uint generation;
    uint tick;
    uint graphVersion;
    uint firstHop;
    uint status;
    float cost;
    uint expansions;
    uint destinationNode;
};
cbuffer Parameters : register(b0)
{
    uint nodeCount, edgeCount, requestCount, graphVersion, maxExpansions;
    float lookAheadCost;
};
StructuredBuffer<Node> nodes : register(t0);
StructuredBuffer<Edge> edges : register(t1);
StructuredBuffer<Request> requests : register(t2);
RWStructuredBuffer<Result> results : register(u0);
groupshared float distances[2048];
groupshared uint firstHops[2048];
groupshared uint closed[2048];
groupshared float bestCost[64];
groupshared uint bestNode[64];
groupshared uint current, finished, iterations, selected, selectedHash;
uint Mix(uint value)
{
    value ^= value >> 16;
    value *= 0x7feb352d;
    value ^= value >> 15;
    value *= 0x846ca68b;
    return value ^ (value >> 16);
}

[numthreads(64, 1, 1)] void main(uint3 group : SV_GroupID, uint lane : SV_GroupIndex)
{
    if (group.x >= requestCount)
        return;
    Request req = requests[group.x];
    for (uint n = lane; n < nodeCount; n += 64)
    {
        distances[n] = n == req.startNode ? 0.0f : 3.402823466e+38f;
        firstHops[n] = 0xffffffff;
        closed[n] = 0;
    }
    if (lane == 0)
    {
        finished = 0;
        iterations = 0;
        current = 0xffffffff;
        selected = 0xffffffff;
        selectedHash = 0xffffffff;
    }
    GroupMemoryBarrierWithGroupSync();
    bool roam = req.mode == 1;
    bool supported = req.mode <= 1;
    bool valid = supported && req.startNode < nodeCount && (roam || req.goalNode < nodeCount);
    if (valid && (nodes[req.startNode].flags & req.blockedFlags))
        valid = false;
    // HLSL logical operators may evaluate both sides. Root SRVs have no
    // descriptor bounds, so never form an out-of-range optional goal load.
    uint fixedGoal = min(req.goalNode, nodeCount - 1);
    if (valid && !roam && (nodes[fixedGoal].flags & req.blockedFlags))
        valid = false;
    if (valid)
    {
        for (uint iteration = 0; iteration < maxExpansions; ++iteration)
        {
            float cost = 3.402823466e+38f;
            uint candidate = 0xffffffff;
            for (uint n = lane; n < nodeCount; n += 64)
                if (!closed[n] && (distances[n] < cost || (distances[n] == cost && n < candidate)))
                {
                    cost = distances[n];
                    candidate = n;
                }
            bestCost[lane] = cost;
            bestNode[lane] = candidate;
            GroupMemoryBarrierWithGroupSync();
            for (uint width = 32; width > 0; width >>= 1)
            {
                if (lane < width && (bestCost[lane + width] < bestCost[lane] ||
                                     (bestCost[lane + width] == bestCost[lane] &&
                                      bestNode[lane + width] < bestNode[lane])))
                {
                    bestCost[lane] = bestCost[lane + width];
                    bestNode[lane] = bestNode[lane + width];
                }
                GroupMemoryBarrierWithGroupSync();
            }
            if (lane == 0)
            {
                current = bestCost[0] < 3.402823466e+38f ? bestNode[0] : 0xffffffff;
                iterations = iteration + 1;
                if (current == 0xffffffff)
                    finished = 2;
                else if (!roam && current == req.goalNode)
                    finished = 1;
                else
                {
                    closed[current] = 1;
                    if (roam)
                    {
                        float3 position = nodes[current].position;
                        float2 radial = position.xy - float2(req.circleX, req.circleY);
                        float3 travel = position - float3(req.originX, req.originY, req.originZ);
                        uint rank = Mix(req.seed ^ current);
                        if (dot(radial, radial) <= req.circleRadius * req.circleRadius &&
                            dot(travel, travel) > req.minDistance * req.minDistance &&
                            (selected == 0xffffffff || rank < selectedHash ||
                             (rank == selectedHash && current < selected)))
                        {
                            selected = current;
                            selectedHash = rank;
                        }
                    }
                }
            }
            GroupMemoryBarrierWithGroupSync();
            if (finished != 0)
                break;
            // Each lane owns destinations, preventing races for duplicate edges.
            Node source = nodes[current];
            for (uint destination = lane; destination < nodeCount; destination += 64)
            {
                if (closed[destination] || (nodes[destination].flags & req.blockedFlags))
                    continue;
                float updated = distances[destination];
                for (uint e = source.firstEdge; e < source.firstEdge + source.edgeCount; ++e)
                {
                    Edge edge = edges[e];
                    if (edge.destination == destination && !(edge.flags & req.blockedFlags))
                        updated = min(updated, distances[current] + edge.cost);
                }
                if (updated < distances[destination])
                {
                    distances[destination] = updated;
                    firstHops[destination] =
                        current == req.startNode || distances[current] < lookAheadCost
                            ? destination
                            : firstHops[current];
                }
            }
            GroupMemoryBarrierWithGroupSync();
        }
    }
    if (lane == 0)
    {
        Result result;
        result.slot = req.slot;
        result.generation = req.generation;
        result.tick = req.tick;
        uint destination = roam ? selected : req.goalNode;
        bool found = valid && (roam ? selected != 0xffffffff : finished == 1);
        result.graphVersion = graphVersion;
        result.status =
            !supported ? 6 : (!valid ? 4 : (found ? 1 : (finished == 0 ? 3 : (roam ? 5 : 2))));
        uint safeDestination = min(destination, nodeCount - 1);
        result.firstHop =
            found ? (req.startNode == destination ? req.startNode : firstHops[safeDestination])
                  : 0xffffffff;
        result.cost = found ? distances[safeDestination] : 0.0f;
        result.destinationNode = found ? destination : 0xffffffff;
        result.expansions = iterations;
        results[group.x] = result;
    }
}
