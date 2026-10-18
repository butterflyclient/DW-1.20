#pragma once
#include "sv_host_navigation.h"

namespace HostScale
{
constexpr uint32_t NavGraphMaxNodes = 2048, NavGraphMaxEdges = 16384;
struct NavGraphNode
{
    Vec3 position;
    uint32_t firstEdge, edgeCount;
    uint64_t areaIdentity;
};
struct NavGraphEdge
{
    uint32_t destination;
    float cost;
    Vec3 portal;
};
enum class NavGraphResult : uint32_t
{
    Ready,
    InvalidHandle,
    UnsupportedArea,
    DifferentSpace,
    GoalOutsidePartition,
    InvalidGeometry
};
struct NavGraphSnapshot
{
    uint64_t epoch;
    uint64_t spaceIdentity;
    float spaceTransform[16];
    NavSearchSpec specification;
    uint32_t nodeCount, edgeCount, startNode, goalNode;
    uint32_t excludedAreas, clippedEdges;
    uint32_t identityLookup[4096]; // node index + 1; zero means empty
    NavGraphNode nodes[NavGraphMaxNodes];
    NavGraphEdge edges[NavGraphMaxEdges];
};
// Synchronous server-navigation safe phase only: the owner must exclude
// native resource mutation for this whole call. Handles stay owned by caller.
// Output owns values only. Epoch must change on map/resource/space/obstacle
// updates; consume only within that epoch and validate the native corridor.
// This conservative portal subgraph excludes dynamic cuts and special links.
NavGraphResult GatherNavGraph(const NavAreaHandle &start, const NavAreaHandle &goal,
                              const NavSearchSpec &spec, uint64_t epoch, NavGraphSnapshot &output,
                              uint32_t nodeLimit = NavGraphMaxNodes,
                              uint32_t edgeLimit = NavGraphMaxEdges);
// Identities are comparison tokens only and are never cast back to pointers.
// Caller supplies a live owned handle and the current capture-frame epoch.
uint32_t FindNavGraphNode(const NavGraphSnapshot &, const NavAreaHandle &, uint64_t expectedEpoch);
} // namespace HostScale
