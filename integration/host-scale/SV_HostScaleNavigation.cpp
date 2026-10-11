#include "sv_host_navigation.h"
#include "com_debugstates.h"

extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId();

namespace
{
    uint32_t s_owner, s_spatial, s_graph, s_frameSpatial, s_frameGraph;
    int32_t s_time = -1;
    uint32_t s_queries, s_deferred, s_cached, s_fallbacks, s_nodes, s_edges;
    uint32_t s_closestQueries, s_closestFallbacks;
    uint32_t s_botOwner, s_closestLimited, s_closestWork;
    HostScale::NavClosestBudget *s_closestBudget;
    bool s_closestSuspended;
    bool s_routeQuery;

    bool OwnsBotScope()
    {
        const uint32_t owner = __atomic_load_n(&s_botOwner, __ATOMIC_ACQUIRE);
        return owner && owner == GetCurrentThreadId();
    }

    bool OwnsScope()
    {
        const uint32_t owner = __atomic_load_n(&s_owner, __ATOMIC_ACQUIRE);
        return owner && owner == GetCurrentThreadId();
    }
}

extern "C" bool SV_HostNav_BeginBot()
{
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&s_botOwner, &expected, GetCurrentThreadId(), false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

extern "C" bool SV_HostNav_OwnsBotScope()
{
    return OwnsBotScope();
}

extern "C" void SV_HostNav_EndBot()
{
    if (!OwnsBotScope())
        return;
    s_closestBudget = nullptr;
    s_closestSuspended = false;
    __atomic_store_n(&s_botOwner, 0u, __ATOMIC_RELEASE);
}

extern "C" HostScale::NavClosestBudget *SV_HostNav_SetClosestBudget(HostScale::NavClosestBudget *budget)
{
    if (!OwnsBotScope() || s_closestSuspended)
        return nullptr;
    auto *previous = s_closestBudget;
    s_closestBudget = budget;
    return previous;
}

extern "C" HostScale::NavClosestBudget *SV_HostNav_GetClosestBudget()
{
    return OwnsBotScope() && !s_closestSuspended ? s_closestBudget : nullptr;
}

extern "C" bool SV_HostNav_SuspendClosest(bool suspended)
{
    if (!OwnsBotScope())
        return false;
    const bool previous = s_closestSuspended;
    s_closestSuspended = suspended;
    return previous;
}

extern "C" void SV_HostNav_RecordClosestBudget(const HostScale::NavClosestBudget *budget)
{
    __atomic_fetch_add(&s_closestWork, budget->work, __ATOMIC_RELAXED);
    if (budget->exhausted)
        __atomic_fetch_add(&s_closestLimited, 1u, __ATOMIC_RELAXED);
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
        s_frameSpatial = population > 96 ? 2048 : 8192;
        s_frameGraph = population > 96 ? 8192 : 32768;
    }
    s_spatial = 512;
    s_graph = 2048;
    s_routeQuery = false;
    // Cap expensive destination discovery at four slots on large servers.
    // Native movement and following an existing path still run every tick.
    const unsigned allowance = population > 96 ? 4 : 16;
    const unsigned groups = (population + allowance - 1) / allowance;
    const unsigned frame = SVHS_FrameDuration > 0 ? unsigned(SVHS_FrameDuration) : 16;
    const bool admitted = groups && ordinal % groups == (uint32_t(now) / frame) % groups &&
                          s_frameSpatial && s_frameGraph;
    __atomic_fetch_add(admitted ? &s_queries : &s_deferred, 1, __ATOMIC_RELAXED);
    return admitted ? 1 : 2;
}

extern "C" bool SV_HostNav_BeginRouteProjection()
{
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&s_owner, &expected, GetCurrentThreadId(), false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return false;
    // The mesh follower already permits at most two plans per frame. Give each
    // an independent bounded projection, so script discovery cannot starve it.
    s_spatial = 512;
    s_graph = 2048;
    s_routeQuery = true;
    return true;
}

extern "C" void SV_HostNav_End(unsigned result)
{
    if (result == 1)
        __atomic_fetch_add(&s_fallbacks, 1, __ATOMIC_RELAXED);
    if (result == 2)
        __atomic_fetch_add(&s_cached, 1, __ATOMIC_RELAXED);
    s_routeQuery = false;
    __atomic_store_n(&s_owner, 0u, __ATOMIC_RELEASE);
}

extern "C" bool SV_HostNav_HasWork()
{
    return !OwnsScope() || (s_spatial && s_graph && (s_routeQuery || (s_frameSpatial && s_frameGraph)));
}

extern "C" bool SV_HostNav_SpatialWork()
{
    if (!OwnsScope())
        return true;
    if (!s_spatial || !s_graph || (!s_routeQuery && (!s_frameSpatial || !s_frameGraph)))
        return false;
    --s_spatial;
    if (!s_routeQuery)
        --s_frameSpatial;
    __atomic_fetch_add(&s_nodes, 1, __ATOMIC_RELAXED);
    return true;
}

extern "C" bool SV_HostNav_GraphWork()
{
    if (!OwnsScope())
        return true;
    if (!s_graph || (!s_routeQuery && !s_frameGraph))
        return false;
    --s_graph;
    if (!s_routeQuery)
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
    Com_Printf(15, "Bot closest-area budget: %u bounded searches, %u visited nodes/candidates\n",
        __atomic_load_n(&s_closestLimited, __ATOMIC_RELAXED),
        __atomic_load_n(&s_closestWork, __ATOMIC_RELAXED));
}

extern "C" void SV_HostNav_RecordClosest(bool fallback)
{
    __atomic_fetch_add(&s_closestQueries, 1, __ATOMIC_RELAXED);
    if (fallback)
        __atomic_fetch_add(&s_closestFallbacks, 1, __ATOMIC_RELAXED);
}
