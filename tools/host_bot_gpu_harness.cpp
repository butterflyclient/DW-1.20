// Standalone owner-run hardware harness. Link SV_HostBotGpu.cpp with
// d3d12.lib dxgi.lib; prepare the generated shader header first.
// This executable is not run by preparation or the production game build.
#include "../integration/host-scale/SV_HostBotGpu.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
using namespace HostBotGpu;
double Microseconds(const LARGE_INTEGER &start, const LARGE_INTEGER &end, const LARGE_INTEGER &frequency)
{
    return double(end.QuadPart-start.QuadPart)*1000000.0/double(frequency.QuadPart);
}
int main()
{
    Config config = {}; config.allowAnyHardwareAdapter = true;
    config.maxExpansions = MaxNodes; config.timeoutMs = 5000;
    if (!Initialize(config)) { puts("SKIP: no usable hardware D3D12 compute device"); return 77; }
    Node nodes[] = {{0,0,0,0,2,0},{1,0,0,2,1,0},{0,1,0,3,1,0},{2,0,0,4,0,0}};
    Edge edges[] = {{1,10,0},{2,1,0},{3,1,0},{1,1,0}};
    Graph graph = {nodes,edges,4,4,123};
    Request requests[MaxBots] = {};
    for (uint32_t i=0;i<MaxBots;++i) requests[i] = {i,41,900,0,3,0};
    if (!Submit(graph,requests,MaxBots)) return 1;
    Result results[MaxBots]; uint32_t count=0;
    uint64_t deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); Sleep(1); }
    if (count != MaxBots) { puts("FAIL: GPU completion"); return 2; }
    for (uint32_t i=0;i<count;++i)
        if (results[i].slot!=i || results[i].generation!=41 || results[i].tick!=900 ||
            results[i].graphVersion!=123 || results[i].status!=Route ||
            results[i].firstHop!=2 || results[i].cost!=3.0f) {
            puts("FAIL: weighted route/identity"); return 3;
        }
    // In-flight copies must retain version123 even when caller changes graph.
    if (!Submit(graph,requests,MaxBots)) return 4;
    graph.version=124; edges[1].cost=50;
    count=0; deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); Sleep(1); }
    if (count!=MaxBots || results[0].graphVersion!=123 || results[0].firstHop!=2) return 5;
    // Blocked goal and disconnected reverse traversal must not produce routes.
    nodes[3].flags=1;
    for (uint32_t i=0;i<MaxBots;++i) requests[i].blockedFlags=1;
    if (!Submit(graph,requests,MaxBots)) return 6;
    count=0; deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); Sleep(1); }
    if (count!=MaxBots || results[0].status!=Invalid) return 7;
    nodes[3].flags=0;
    for (uint32_t i=0;i<MaxBots;++i) { requests[i].startNode=3; requests[i].goalNode=0; }
    if (!Submit(graph,requests,MaxBots)) return 8;
    count=0; deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); Sleep(1); }
    if (count!=MaxBots || results[0].status!=Unreachable) return 9;
    edges[0].cost=-1;
    if (Submit(graph,requests,MaxBots) || !GetMetrics().invalid) return 10;
    edges[0].cost=10;
    Disable(); Poll(nullptr,0);
    config.maxExpansions=1;
    if (!Initialize(config)) return 11;
    requests[0]={0,42,901,0,3,0};
    if (!Submit(graph,requests,1)) return 12;
    count=0; deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); Sleep(1); }
    if (count!=1 || results[0].status!=BudgetExceeded || results[0].firstHop!=InvalidNode) return 13;
    Disable(); Poll(nullptr,0);
    config.maxExpansions=MaxNodes;
    if (!Initialize(config)) return 14;
    Node grid[256]={}; Edge gridEdges[1024]={}; uint32_t edgeCount=0;
    for (uint32_t n=0;n<256;++n) {
        grid[n].firstEdge=edgeCount;
        uint32_t x=n%16,y=n/16;
        if (x) gridEdges[edgeCount++]={n-1,1,0};
        if (x<15) gridEdges[edgeCount++]={n+1,1,0};
        if (y) gridEdges[edgeCount++]={n-16,1,0};
        if (y<15) gridEdges[edgeCount++]={n+16,1,0};
        grid[n].edgeCount=edgeCount-grid[n].firstEdge;
    }
    Graph stressGraph={grid,gridEdges,256,edgeCount,777};
    for (uint32_t i=0;i<MaxBots;++i) requests[i]={i,43,902,0,255,0};
    LARGE_INTEGER frequency,begin,submitted,finished; QueryPerformanceFrequency(&frequency);
    double totalSubmit=0,maxSubmit=0,totalCompletion=0,maxCompletion=0;
    uint64_t totalGpu=0;
    for (unsigned iteration=0;iteration<120;++iteration) {
        QueryPerformanceCounter(&begin);
        if (!Submit(stressGraph,requests,MaxBots)) return 15;
        QueryPerformanceCounter(&submitted);
        count=0; deadline=GetTickCount64()+5000;
        while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); SwitchToThread(); }
        QueryPerformanceCounter(&finished);
        if (count!=MaxBots) return 16;
        for (uint32_t i=0;i<count;++i)
            if (results[i].status!=Route || results[i].cost!=30.0f || results[i].firstHop!=1 ||
                results[i].slot!=i || results[i].generation!=43 || results[i].graphVersion!=777) return 17;
        double submit=Microseconds(begin,submitted,frequency),completion=Microseconds(begin,finished,frequency);
        totalSubmit+=submit; if (submit>maxSubmit) maxSubmit=submit;
        totalCompletion+=completion; if (completion>maxCompletion) maxCompletion=completion;
        totalGpu+=GetMetrics().lastGpuMicroseconds;
    }
    // Queue capacity is bounded and a fourth batch returns immediately.
    for (unsigned i=0;i<3;++i) if (!Submit(stressGraph,requests,MaxBots)) return 18;
    if (Submit(stressGraph,requests,MaxBots)) return 19;
    Result ring[MaxBots*3]; uint32_t retired=0; deadline=GetTickCount64()+5000;
    while (retired<MaxBots*3 && GetTickCount64()<deadline) {
        retired+=Poll(ring+retired,MaxBots*3-retired); SwitchToThread();
    }
    if (retired!=MaxBots*3) return 20;
    Metrics metrics=GetMetrics();
    printf("HARDWARE vendor=0x%04x device=0x%04x luid=%08x:%08x timestamp_hz=%llu\n",
           metrics.adapterVendor,metrics.adapterDevice,unsigned(metrics.adapterLuidHigh),metrics.adapterLuidLow,
           static_cast<unsigned long long>(metrics.gpuTimestampFrequency));
    printf("STRESS batches=120 bots_per_batch=200 nodes=256 edges=%u checked_routes=24000\n",edgeCount);
    printf("TIMING submit_cpu_us_avg=%.3f max=%.3f submit_to_readback_us_avg=%.3f max=%.3f gpu_dispatch_us_avg=%.3f max=%llu\n",
           totalSubmit/120,maxSubmit,totalCompletion/120,maxCompletion,double(totalGpu)/120,
           static_cast<unsigned long long>(metrics.maxGpuMicroseconds));
    printf("METRICS submitted=%llu completed=%llu busy=%llu pending=%u device_failures=%llu timeouts=%llu\n",
           static_cast<unsigned long long>(metrics.submitted),static_cast<unsigned long long>(metrics.completed),
           static_cast<unsigned long long>(metrics.busy),metrics.pending,
           static_cast<unsigned long long>(metrics.deviceFailures),static_cast<unsigned long long>(metrics.timeouts));
    Disable(); Poll(nullptr,0);
    // Weighted branch 0->2->1->3 has costs 1+1+1. A threshold of 1.5
    // must select node1, preserving the correct branch instead of direct0->1.
    config.lookAheadCost=1.5f;
    if (!Initialize(config)) return 21;
    requests[0]={0,44,903,0,3,0};
    edges[1].cost=1;
    if (!Submit(graph,requests,1)) return 22;
    count=0; deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); SwitchToThread(); }
    if (count!=1 || results[0].status!=Route || results[0].firstHop!=1 || results[0].cost!=3.0f) return 23;
    Disable(); Poll(nullptr,0);
    // Threshold beyond the route length selects the settled goal.
    config.lookAheadCost=512.0f;
    if (!Initialize(config)) return 24;
    if (!Submit(graph,requests,1)) return 25;
    count=0; deadline=GetTickCount64()+5000;
    while (!count && GetTickCount64()<deadline) { count=Poll(results,MaxBots); SwitchToThread(); }
    if (count!=1 || results[0].status!=Route || results[0].firstHop!=3 || results[0].cost!=3.0f) return 26;
    Disable(); Poll(nullptr,0);
    puts("PASS: real hardware weighted Dijkstra, 200 bots, immutable graph and identity, 120-batch stress, weighted route lookahead");
    return 0;
}
