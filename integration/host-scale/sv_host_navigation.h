#pragma once
#include "sv_host_scale.h"

namespace HostScale
{
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
    static_assert(offsetof(NavSearchStep, looseAreas) == 4160);
    static_assert(offsetof(NavSearchStep, subArea) == 4176 && sizeof(NavSearchStep) == 4192);
}

extern "C"
{
    // Zero: no scope; one: admit a query; two: defer this bot's query.
    unsigned SV_HostNav_Begin(unsigned occupiedOrdinal, unsigned population);
    void SV_HostNav_End(unsigned result); // 0=native result, 1=fallback, 2=cached result
    bool SV_HostNav_SpatialWork();
    bool SV_HostNav_GraphWork();
    bool SV_HostNav_HasWork();
    void SV_HostNav_PrintStatus();
    void SV_HostNav_RecordClosest(bool fallback);
    unsigned Bfx_ClosestReachableTreeStep(HostScale::NavTreeWalk *, int);
    unsigned Bfx_ClosestReachableSearchStep(HostScale::NavSearchStep *, int);
    void Bfx_IncrementalSearchToIsland(HostScale::NavIncrementalSearch *, int);
    void Scr_GetClosestReachablePointOnNavmesh(void *, uint32_t);
}
