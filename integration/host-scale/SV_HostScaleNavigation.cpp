#include "sv_host_navigation.h"
#include "com_debugstates.h"

extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId();

namespace
{
    uint32_t s_owner, s_spatial, s_graph, s_frameSpatial, s_frameGraph;
    int32_t s_time = -1;
    uint32_t s_queries, s_deferred, s_cached, s_fallbacks, s_nodes, s_edges;
    uint32_t s_closestQueries, s_closestFallbacks;

    bool OwnsScope()
    {
        const uint32_t owner = __atomic_load_n(&s_owner, __ATOMIC_ACQUIRE);
        return owner && owner == GetCurrentThreadId();
    }
}

extern "C" unsigned SV_HostNav_Begin(unsigned ordinal, unsigned population)
{
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&s_owner, &expected, GetCurrentThreadId(), false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return 0;
    const int32_t now = SVHS_LevelTime;
    if (now != s_time)
    {
        s_time = now;
        s_frameSpatial = 8192;
        s_frameGraph = 32768;
    }
    s_spatial = 512;
    s_graph = 2048;
    // At most sixteen occupied slots receive full script navigation queries per
    // frame. Rotate admission, so later clients cannot starve behind early slots.
    const unsigned groups = (population + 15) / 16;
    const unsigned frame = SVHS_FrameDuration > 0 ? unsigned(SVHS_FrameDuration) : 16;
    const bool admitted = groups && ordinal % groups == (uint32_t(now) / frame) % groups &&
                          s_frameSpatial && s_frameGraph;
    __atomic_fetch_add(admitted ? &s_queries : &s_deferred, 1, __ATOMIC_RELAXED);
    return admitted ? 1 : 2;
}

extern "C" void SV_HostNav_End(unsigned result)
{
    if (result == 1)
        __atomic_fetch_add(&s_fallbacks, 1, __ATOMIC_RELAXED);
    if (result == 2)
        __atomic_fetch_add(&s_cached, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&s_owner, 0u, __ATOMIC_RELEASE);
}

extern "C" bool SV_HostNav_HasWork()
{
    return !OwnsScope() || (s_spatial && s_graph && s_frameSpatial && s_frameGraph);
}

extern "C" bool SV_HostNav_SpatialWork()
{
    if (!OwnsScope())
        return true;
    if (!s_spatial || !s_graph || !s_frameSpatial || !s_frameGraph)
        return false;
    --s_spatial;
    --s_frameSpatial;
    __atomic_fetch_add(&s_nodes, 1, __ATOMIC_RELAXED);
    return true;
}

extern "C" bool SV_HostNav_GraphWork()
{
    if (!OwnsScope())
        return true;
    if (!s_graph || !s_frameGraph)
        return false;
    --s_graph;
    --s_frameGraph;
    __atomic_fetch_add(&s_edges, 1, __ATOMIC_RELAXED);
    return true;
}

extern "C" void SV_HostNav_PrintStatus()
{
    Com_Printf(15, "Script navigation totals: %u searches, %u staggered; "
        "%u cached points, %u current-area fallbacks; %u spatial nodes, %u graph edges\n",
        __atomic_load_n(&s_queries, __ATOMIC_RELAXED),
        __atomic_load_n(&s_deferred, __ATOMIC_RELAXED),
        __atomic_load_n(&s_cached, __ATOMIC_RELAXED),
        __atomic_load_n(&s_fallbacks, __ATOMIC_RELAXED),
        __atomic_load_n(&s_nodes, __ATOMIC_RELAXED),
        __atomic_load_n(&s_edges, __ATOMIC_RELAXED));
    Com_Printf(15, "Closest-area searches: %u nearby probes, %u unrestricted fallbacks\n",
        __atomic_load_n(&s_closestQueries, __ATOMIC_RELAXED),
        __atomic_load_n(&s_closestFallbacks, __ATOMIC_RELAXED));
}

extern "C" void SV_HostNav_RecordClosest(bool fallback)
{
    __atomic_fetch_add(&s_closestQueries, 1, __ATOMIC_RELAXED);
    if (fallback)
        __atomic_fetch_add(&s_closestFallbacks, 1, __ATOMIC_RELAXED);
}
