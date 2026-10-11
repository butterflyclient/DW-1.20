#pragma once
#include "sv_host_scale.h"

namespace HostScale
{
    // Stack-owned by one nearest-area query. No area/resource pointer survives
    // the query. Budgets include both KD nodes and dynamic-area candidates.
    struct NavClosestBudget
    {
        uint32_t work;
        bool exhausted;
    };

    inline bool ClosestWork(NavClosestBudget *budget, bool hasCandidate)
    {
        if (!budget)
            return true;
        // Preserve a larger discovery allowance when filters reject everything.
        // Once a valid area exists, stop spending a whole frame proving it is
        // the absolute nearest area on a large map.
        const unsigned limit = hasCandidate ? 512 : 4096;
        if (budget->work >= limit)
        {
            budget->exhausted = true;
            return false;
        }
        ++budget->work;
        return true;
    }
    // Target-build BFX search views. Handles are borrowed only within a native
    // query; cached results contain coordinates, never retained graph pointers.
    struct NavAreaHandle { void **reference; void *space; };
#pragma pack(push, 4)
    struct Nav2DQueryView
    {
        const uintptr_t *vtable;
        uint8_t navigationState[1180];
        uint8_t pathConfiguration[176];
        NavAreaHandle currentArea;
    };
#pragma pack(pop)
    struct NavSearchSpec
    {
        uint32_t obstacleMode, obstacleFlags, areaFlags, unused12, linkFlags;
    };
    struct NavIsland;
    struct NavEdge
    {
        NavIsland *destination;
        uint8_t open;
        uint8_t unused9[3];
        uint32_t linkFlags;
    };
    struct NavIsland
    {
        uint8_t unused0[8];
        uint32_t visited;
        uint8_t unused12[8];
        uint32_t obstacleFlags, areaFlags;
        uint8_t unused28[4];
        NavEdge *edges;
        int32_t edgeCount;
        uint32_t unused44;
    };
    struct NavReachQueue
    {
        const uint32_t *generation;
        uint64_t capacity;
        NavIsland **storage, **read, **write;
        const NavSearchSpec *spec;
    };
    struct NavIncrementalSearch
    {
        const uint32_t *generation;
        NavIsland ***islands;
        NavReachQueue *queue;
    };
    struct NavTreeEntry { uint8_t *node; float distance, unused12; };
    struct NavClosestAreaArray
    {
        void **items;
        int32_t count, capacity;
        uint32_t allocationFlags, unused20;
    };
    struct NavClosestCollector
    {
        const NavSearchSpec *spec;
        float maximumDistance;
        uint32_t unused12;
        NavClosestAreaArray areas;
        int32_t desiredCount;
        uint8_t unused44[12];
        uint8_t *resource;
    };
    struct NavClosestAreaView
    {
        uint8_t unused0[8];
        uint8_t *children;
        uint8_t unused16[16];
        Vec3 center;
        float radius;
        uint32_t unused48, areaFlags, shapeFlags;
        uint8_t unused60[8];
        uint32_t obstacleFlags;
    };
    struct NavTreeWalk
    {
        Vec3 localPoint, point;
        NavTreeEntry *top;
        uint8_t *collector;
        NavTreeEntry stack[256];
    };
    struct NavAreaList { uint8_t **areas; int32_t count, unused12; };
    struct NavSearchStep
    {
        void *resource;
        Vec3 *point;
        uint8_t *collector;
        NavTreeWalk tree;
        NavAreaList *looseAreas;
        int32_t areaIndex, unused4172;
        uint8_t *subArea;
        int32_t subCount, subIndex;
    };
    static_assert(sizeof(NavAreaHandle) == 16 && sizeof(NavEdge) == 16);
    static_assert(offsetof(Nav2DQueryView, pathConfiguration) == 1188);
    static_assert(offsetof(Nav2DQueryView, currentArea) == 1364 && sizeof(Nav2DQueryView) == 1380);
    static_assert(offsetof(NavIsland, visited) == 8 && offsetof(NavIsland, edges) == 32);
    static_assert(offsetof(NavIsland, edgeCount) == 40 && sizeof(NavIsland) == 48);
    static_assert(sizeof(NavReachQueue) == 48 && sizeof(NavIncrementalSearch) == 24);
    static_assert(offsetof(NavTreeWalk, stack) == 40 && sizeof(NavTreeWalk) == 4136);
    static_assert(sizeof(NavTreeEntry) == 16 && offsetof(NavTreeEntry, distance) == 8);
    static_assert(sizeof(NavClosestAreaArray) == 24 && offsetof(NavClosestAreaArray, allocationFlags) == 16);
    static_assert(offsetof(NavClosestCollector, maximumDistance) == 8);
    static_assert(offsetof(NavClosestCollector, areas) == 16 && offsetof(NavClosestCollector, desiredCount) == 40);
    static_assert(offsetof(NavClosestCollector, resource) == 56 && sizeof(NavClosestCollector) == 64);
    static_assert(offsetof(NavClosestAreaView, center) == 32 && offsetof(NavClosestAreaView, radius) == 44);
    static_assert(offsetof(NavClosestAreaView, shapeFlags) == 56 && sizeof(NavClosestAreaView) == 72);
    static_assert(offsetof(NavSearchStep, looseAreas) == 4160);
    static_assert(offsetof(NavSearchStep, subArea) == 4176 && sizeof(NavSearchStep) == 4192);
}

extern "C"
{
    bool SV_HostNav_BeginBot();
    bool SV_HostNav_OwnsBotScope();
    void SV_HostNav_EndBot();
    void SV_HostNav_RefreshBotMovement(void *, HostScale::UserCmd *);
    HostScale::NavClosestBudget *SV_HostNav_SetClosestBudget(HostScale::NavClosestBudget *);
    HostScale::NavClosestBudget *SV_HostNav_GetClosestBudget();
    bool SV_HostNav_SuspendClosest(bool suspended);
    void SV_HostNav_RecordClosestBudget(const HostScale::NavClosestBudget *);
    // Zero: no scope; one: admit a query; two: defer this bot's query.
    unsigned SV_HostNav_Begin(unsigned occupiedOrdinal, unsigned population);
    bool SV_HostNav_BeginRouteProjection();
    void SV_HostNav_End(unsigned result); // 0=native result, 1=fallback, 2=cached result
    bool SV_HostNav_SpatialWork();
    bool SV_HostNav_GraphWork();
    bool SV_HostNav_HasWork();
    void SV_HostNav_PrintStatus();
    void SV_HostNav_RecordClosest(bool fallback);
    unsigned Bfx_ClosestReachableTreeStep(HostScale::NavTreeWalk *, int);
    unsigned Bfx_ClosestReachableSearchStep(HostScale::NavSearchStep *, int);
    void Bfx_IncrementalSearchToIsland(HostScale::NavIncrementalSearch *, int);
    unsigned Bfx_ClosestAreaTreeStep(HostScale::NavTreeWalk *, int);
    void Bfx_ClosestAreaCollect(HostScale::NavClosestCollector *, HostScale::NavClosestAreaView *, const HostScale::Vec3 *);
    void Scr_GetClosestReachablePointOnNavmesh(void *, uint32_t);
}
