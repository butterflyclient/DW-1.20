#pragma once
#include "../integration/host-scale/SV_HostBotGpu.h"
#include <float.h>
#include <vector>

namespace HostBotGpuReference
{
    inline uint32_t Mix(uint32_t value)
    {
        value ^= value >> 16;
        value *= 0x7feb352d;
        value ^= value >> 15;
        value *= 0x846ca68b;
        return value ^ (value >> 16);
    }

    // Independent serial CPU oracle. It uses edge iteration rather than the shader's
    // destination-owned parallel relaxation. No game/native ABI is modeled here.
    inline HostBotGpu::Result Solve(const HostBotGpu::Graph &graph,
                                    const HostBotGpu::Request &request, uint32_t limit,
                                    float lookAhead)
    {
        using namespace HostBotGpu;
        Result result{};
        result.slot = request.slot;
        result.generation = request.generation;
        result.tick = request.tick;
        result.graphVersion = graph.version;
        result.firstHop = result.destinationNode = InvalidNode;
        if (request.mode > RoamMode)
        {
            result.status = Unsupported;
            return result;
        }
        const bool roam = request.mode == RoamMode;
        if (request.startNode >= graph.nodeCount ||
            (!roam && request.goalNode >= graph.nodeCount) ||
            (graph.nodes[request.startNode].flags & request.blockedFlags) ||
            (!roam && (graph.nodes[request.goalNode].flags & request.blockedFlags)))
        {
            result.status = Invalid;
            return result;
        }
        std::vector<float> distances(graph.nodeCount, FLT_MAX);
        std::vector<uint32_t> first(graph.nodeCount, InvalidNode);
        std::vector<bool> closed(graph.nodeCount, false);
        distances[request.startNode] = 0;
        uint32_t selected = InvalidNode, rank = InvalidNode;
        bool exhausted = false, reached = false;
        for (uint32_t iteration = 0; iteration < limit; ++iteration)
        {
            uint32_t current = InvalidNode;
            float cost = FLT_MAX;
            for (uint32_t i = 0; i < graph.nodeCount; ++i)
            {
                if (!closed[i] && distances[i] < cost)
                {
                    current = i;
                    cost = distances[i];
                }
            }
            result.expansions = iteration + 1;
            if (current == InvalidNode)
            {
                exhausted = true;
                break;
            }
            if (!roam && current == request.goalNode)
            {
                reached = true;
                break;
            }
            closed[current] = true;
            const auto &node = graph.nodes[current];
            if (roam)
            {
                const float x = node.x - request.circleX, y = node.y - request.circleY;
                const float dx = node.x - request.originX, dy = node.y - request.originY;
                const float dz = node.z - request.originZ;
                const uint32_t candidateRank = Mix(request.seed ^ current);
                if (x * x + y * y <= request.circleRadius * request.circleRadius &&
                    dx * dx + dy * dy + dz * dz > request.minDistance * request.minDistance &&
                    (selected == InvalidNode || candidateRank < rank ||
                     (candidateRank == rank && current < selected)))
                {
                    selected = current;
                    rank = candidateRank;
                }
            }
            for (uint32_t e = node.firstEdge; e < node.firstEdge + node.edgeCount; ++e)
            {
                const auto &edge = graph.edges[e];
                const uint32_t next = edge.destination;
                if (closed[next] || (graph.nodes[next].flags & request.blockedFlags) ||
                    (edge.flags & request.blockedFlags))
                    continue;
                const float updated = cost + edge.cost;
                if (updated < distances[next])
                {
                    distances[next] = updated;
                    first[next] =
                        current == request.startNode || cost < lookAhead ? next : first[current];
                }
            }
        }
        const uint32_t destination = roam ? selected : request.goalNode;
        const bool found = roam ? selected != InvalidNode : reached;
        result.status =
            found ? Route : (!exhausted ? BudgetExceeded : (roam ? NoEligible : Unreachable));
        if (found)
        {
            result.destinationNode = destination;
            result.firstHop = destination == request.startNode ? destination : first[destination];
            result.cost = distances[destination];
        }
        return result;
    }
} // namespace HostBotGpuReference
