// Standalone real D3D12 test. It neither opens nor modifies a game process.
#include "../integration/host-scale/SV_HostBotGpu.h"
#include "host_bot_gpu_reference.h"
#define WIN32_LEAN_AND_MEAN
#include <cmath>
#include <cstdio>
#include <random>
#include <set>
#include <vector>
#include <windows.h>

using namespace HostBotGpu;

static bool Run(const Graph &graph, const std::vector<Request> &requests,
                const Config &configuration, unsigned &checked)
{
    if (!Submit(graph, requests.data(), uint32_t(requests.size())))
    {
        const auto metrics = GetMetrics();
        std::printf("FAIL submit invalid=%llu error=%d\n",
                    static_cast<unsigned long long>(metrics.invalid), metrics.lastError);
        return false;
    }
    Result results[MaxBots]{};
    uint32_t count = 0;
    const uint64_t deadline = GetTickCount64() + 5000;
    while (!count && GetTickCount64() < deadline)
    {
        count = Poll(results, MaxBots);
        SwitchToThread();
    }
    if (count != requests.size())
    {
        const auto metrics = GetMetrics();
        std::printf("FAIL completion count=%u expected=%zu error=%d enabled=%u pending=%u "
                    "submitted=%llu completed=%llu failures=%llu timeouts=%llu\n",
                    count, requests.size(), metrics.lastError, metrics.enabled, metrics.pending,
                    static_cast<unsigned long long>(metrics.submitted),
                    static_cast<unsigned long long>(metrics.completed),
                    static_cast<unsigned long long>(metrics.deviceFailures),
                    static_cast<unsigned long long>(metrics.timeouts));
        return false;
    }
    for (uint32_t i = 0; i < count; ++i)
    {
        const Result expected = HostBotGpuReference::Solve(
            graph, requests[i], configuration.maxExpansions, configuration.lookAheadCost);
        const auto &actual = results[i];
        if (actual.slot != expected.slot || actual.generation != expected.generation ||
            actual.tick != expected.tick || actual.graphVersion != expected.graphVersion ||
            actual.status != expected.status || actual.firstHop != expected.firstHop ||
            actual.destinationNode != expected.destinationNode ||
            actual.expansions != expected.expansions ||
            std::fabs(actual.cost - expected.cost) > 0.001f)
        {
            std::printf("FAIL request=%u mode=%u status=%u/%u destination=%u/%u hop=%u/%u "
                        "expansions=%u/%u cost=%f/%f\n",
                        i, requests[i].mode, actual.status, expected.status, actual.destinationNode,
                        expected.destinationNode, actual.firstHop, expected.firstHop,
                        actual.expansions, expected.expansions, actual.cost, expected.cost);
            return false;
        }
        ++checked;
    }
    return true;
}

int main()
{
    Config configuration{};
    configuration.allowAnyHardwareAdapter = true;
    configuration.maxExpansions = 64;
    configuration.timeoutMs = 5000;
    configuration.lookAheadCost = 512;
    if (!Initialize(configuration))
        return 77;
    unsigned checked = 0;
    std::mt19937 random(0x42524750);
    // Both navigation layer bits and dynamic blockers are represented as graph
    // flags, not invented engine layer numbers. The planner supplies the graph.
    for (unsigned batch = 0; batch < 40; ++batch)
    {
        const uint32_t size = 24 + random() % 105;
        std::vector<Node> nodes(size);
        std::vector<Edge> edges;
        for (uint32_t i = 0; i < size; ++i)
        {
            auto &node = nodes[i];
            node.x = float(int(random() % 65) - 32) * 128;
            node.y = float(int(random() % 65) - 32) * 128;
            node.z = i % 2 ? 0.0f : 2048.0f;
            node.flags = random() % 7 == 0 ? 1 : 0;
            node.firstEdge = uint32_t(edges.size());
            for (unsigned edge = 0; edge < 5; ++edge)
                edges.push_back(
                    {random() % size, float(1 + random() % 64) * 16, random() % 9 == 0 ? 1u : 0u});
            node.edgeCount = uint32_t(edges.size()) - node.firstEdge;
        }
        Graph graph{nodes.data(), edges.data(), size, uint32_t(edges.size()), batch + 1};
        std::vector<Request> requests(MaxBots);
        for (uint32_t i = 0; i < MaxBots; ++i)
        {
            auto &request = requests[i];
            request.slot = i;
            request.generation = 100 + batch;
            request.tick = 1000 + batch;
            request.startNode = random() % size;
            request.goalNode = random() % size;
            request.blockedFlags = i % 3 == 0 ? 1 : 0;
            request.mode = i % 4 == 0 ? RouteMode : RoamMode;
            request.minDistance = MinimumRoamDistance;
            request.seed = random();
            request.circleX = float(int(random() % 17) - 8) * 128;
            request.circleY = float(int(random() % 17) - 8) * 128;
            request.circleRadius = float(256 + random() % 4096);
            request.originX = nodes[request.startNode].x;
            request.originY = nodes[request.startNode].y;
            request.originZ = nodes[request.startNode].z;
        }
        if (!Run(graph, requests, configuration, checked))
            return 1;
    }
    Node nodes[] = {
        {0, 0, 0, 0, 2, 0}, {1056, 0, 0, 2, 1, 0}, {2048, 0, 0, 3, 0, 0}, {0, 2048, 0, 3, 0, 0}};
    Edge edges[] = {{1, 16, 0}, {2, 32, 0}, {3, 16, 1}};
    Graph graph{nodes, edges, 4, 3, 90};
    std::vector<Request> requests(MaxBots);
    std::set<uint32_t> expectedVariation;
    for (uint32_t i = 0; i < MaxBots; ++i)
    {
        auto &request = requests[i];
        request.slot = i;
        request.startNode = 0;
        request.goalNode = InvalidNode;
        request.mode = RoamMode;
        request.minDistance = MinimumRoamDistance;
        request.seed = i;
        request.circleRadius = i % 3 == 0 ? 1000.0f : 3000.0f;
        request.blockedFlags = i % 2 == 0 ? 1 : 0;
        const auto expected = HostBotGpuReference::Solve(graph, request, 64, 512);
        if (expected.status == Route)
            expectedVariation.insert(expected.destinationNode);
    }
    if (expectedVariation.size() != 2 || !Run(graph, requests, configuration, checked))
        return 2;
    requests.resize(1);
    requests[0].mode = 9;
    if (!Run(graph, requests, configuration, checked))
        return 3;
    requests[0].mode = RoamMode;
    requests[0].circleRadius = std::nanf("");
    if (Submit(graph, requests.data(), 1))
        return 4;
    requests[0].circleRadius = 3000;
    requests[0].minDistance = 1024;
    if (Submit(graph, requests.data(), 1))
        return 5;
    // A small expansion budget cannot turn an unvisited far node into a goal.
    Disable();
    Poll(nullptr, 0);
    configuration.maxExpansions = 1;
    if (!Initialize(configuration))
        return 6;
    requests[0].minDistance = MinimumRoamDistance;
    if (!Run(graph, requests, configuration, checked))
        return 7;
    const auto metrics = GetMetrics();
    std::printf("ROAM hardware_checks=%u randomized_batches=40 randomized_requests=8000 "
                "mixed_route_requests=2000 circle_flags_layers=PASS min_distance_boundary=PASS "
                "noeligible=PASS seeded_variation=PASS unsupported=PASS invalid_inputs=PASS\n",
                checked);
    std::printf("ROAM_TIMING last_gpu_us=%llu max_gpu_us=%llu device_failures=%llu timeouts=%llu\n",
                static_cast<unsigned long long>(metrics.lastGpuMicroseconds),
                static_cast<unsigned long long>(metrics.maxGpuMicroseconds),
                static_cast<unsigned long long>(metrics.deviceFailures),
                static_cast<unsigned long long>(metrics.timeouts));
    Disable();
    Poll(nullptr, 0);
    return 0;
}
