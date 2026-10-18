#pragma once
#include <stdint.h>
namespace HostBotGpu
{
    constexpr uint32_t MaxBots = 200, MaxNodes = 2048, MaxEdges = 16384;
    constexpr uint32_t InvalidNode = 0xffffffffu;
    struct Node
    {
        float x, y, z;
        uint32_t firstEdge, edgeCount, flags;
    };
    struct Edge
    {
        uint32_t destination;
        float cost;
        uint32_t flags;
    };
    enum RequestMode : uint32_t
    {
        RouteMode = 0,
        RoamMode = 1
    };
    constexpr uint32_t ShaderAbiVersion = 2;
    constexpr float MinimumRoamDistance = 1056.0f;
    struct Request
    {
        uint32_t slot, generation, tick, startNode, goalNode, blockedFlags;
        uint32_t mode = RouteMode;
        uint32_t seed = 0;
        // Roaming samples reachable native node centers, not uniform circle area.
        // Caller supplies an already inset positive circle radius.
        float circleX = 0, circleY = 0, circleRadius = 0;
        float minDistance = 0;
        float originX = 0, originY = 0, originZ = 0;
    };
    enum Status : uint32_t
    {
        Route = 1,
        Unreachable = 2,
        BudgetExceeded = 3,
        Invalid = 4,
        NoEligible = 5,
        Unsupported = 6
    };
    // firstHop is a route waypoint when Config.lookAheadCost is positive.
    struct Result
    {
        uint32_t slot, generation, tick, graphVersion, firstHop, status;
        float cost;
        uint32_t expansions;
        uint32_t destinationNode;
    };
    struct Graph
    {
        const Node *nodes;
        const Edge *edges;
        uint32_t nodeCount, edgeCount, version;
    };
    struct Config
    {
        uint32_t adapterLuidLow;
        int32_t adapterLuidHigh;
        bool allowAnyHardwareAdapter;
        uint32_t maxExpansions, timeoutMs;
        // Zero returns the exact first hop. Positive cost selects the first node
        // reaching this distance along the settled shortest route (or its goal).
        // The caller must project and natively validate this route waypoint.
        float lookAheadCost;
    };
    struct Metrics
    {
        uint64_t submitted, completed, busy, invalid, timeouts, deviceFailures;
        uint32_t pending, enabled;
        int32_t lastError;
        uint32_t adapterVendor, adapterDevice, adapterLuidLow;
        int32_t adapterLuidHigh;
        uint64_t gpuTimestampFrequency, lastGpuMicroseconds, maxGpuMicroseconds;
    };
    // Initialize on a frontend thread before a match, then release-publish readiness
    // and acquire it on the server thread. D3D12 COM objects allow this ownership
    // handoff; callers must never access this API concurrently. After initialization,
    // one owning server thread only. All Submit/Poll
    // calls are nonblocking. False/zero always means use native CPU planning.
    bool Initialize(const Config &config);
    bool Submit(const Graph &graph, const Request *requests, uint32_t count);
    uint32_t Poll(Result *results, uint32_t capacity);
    Metrics GetMetrics();
    // Disable never frees resources still referenced by GPU commands. Poll retires
    // them when completed; process lifetime owns resources if a device hangs.
    void Disable();
} // namespace HostBotGpu
