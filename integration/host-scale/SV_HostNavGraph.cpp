#include "SV_HostNavGraph.h"

namespace HostScale
{
namespace
{
template <class T> T Read(const void *p, size_t offset)
{
    T value;
    __builtin_memcpy(&value, static_cast<const uint8_t *>(p) + offset, sizeof(T));
    return value;
}
const uint8_t *Area(const NavAreaHandle &handle)
{
    return handle.reference ? static_cast<const uint8_t *>(*handle.reference) : nullptr;
}
uint32_t Bucket(uint64_t identity)
{
    identity ^= identity >> 33;
    identity *= 0xff51afd7ed558ccdULL;
    identity ^= identity >> 33;
    return uint32_t(identity) & 4095u;
}
uint32_t Lookup(const NavGraphSnapshot &out, uint64_t identity)
{
    uint32_t bucket = Bucket(identity);
    for (uint32_t count = 0; count < 4096; ++count, bucket = (bucket + 1) & 4095u)
    {
        const uint32_t entry = out.identityLookup[bucket];
        if (!entry)
            return ~0u;
        if (entry <= out.nodeCount && out.nodes[entry - 1].areaIdentity == identity)
            return entry - 1;
    }
    return ~0u;
}
void Insert(NavGraphSnapshot &out, uint32_t id, uint64_t identity)
{
    uint32_t bucket = Bucket(identity);
    while (out.identityLookup[bucket])
        bucket = (bucket + 1) & 4095u;
    out.nodes[id].areaIdentity = identity;
    out.identityLookup[bucket] = id + 1;
}
bool Supported(const uint8_t *area, const NavSearchSpec &spec)
{
    // +8 is the dynamic child container, +16 the special-link list.
    // Replay 0x141FDE030 returns the parent when its child count is zero.
    const void *children = Read<void *>(area, 8);
    const uint32_t shape = Read<uint32_t>(area, 56);
    const uint32_t usage = Read<uint32_t>(area, 52);
    return (!children || Read<uint32_t>(children, 0) == 0) && !Read<void *>(area, 16) &&
           !(shape & 0x20000000u) && (shape & 127u) >= 3 && (!usage || (usage & spec.areaFlags));
}
Vec3 World(const void *space, const Vec3 &p)
{
    // Replay 0x141FC7FD0 and 0x141FAA880: affine matrix at space+76.
    const float *m = reinterpret_cast<const float *>(static_cast<const uint8_t *>(space) + 76);
    return {p.x * m[0] + p.y * m[4] + p.z * m[8] + m[12],
            p.x * m[1] + p.y * m[5] + p.z * m[9] + m[13],
            p.x * m[2] + p.y * m[6] + p.z * m[10] + m[14]};
}
bool Finite(const Vec3 &v)
{
    return __builtin_isfinite(v.x) && __builtin_isfinite(v.y) && __builtin_isfinite(v.z);
}
float Distance(const Vec3 &a, const Vec3 &b)
{
    const float x = a.x - b.x, y = a.y - b.y, z = a.z - b.z;
    return __builtin_sqrtf(x * x + y * y + z * z);
}
} // namespace
uint32_t FindNavGraphNode(const NavGraphSnapshot &out, const NavAreaHandle &handle, uint64_t epoch)
{
    if (out.epoch != epoch || !handle.space ||
        out.spaceIdentity != reinterpret_cast<uint64_t>(handle.space))
        return ~0u;
    if (__builtin_memcmp(out.spaceTransform, static_cast<const uint8_t *>(handle.space) + 76,
                         sizeof(out.spaceTransform)))
        return ~0u;
    const uint8_t *area = Area(handle);
    return area ? Lookup(out, reinterpret_cast<uint64_t>(area)) : ~0u;
}
NavGraphResult GatherNavGraph(const NavAreaHandle &start, const NavAreaHandle &goal,
                              const NavSearchSpec &spec, uint64_t epoch, NavGraphSnapshot &out,
                              uint32_t nodeLimit, uint32_t edgeLimit)
{
    out.epoch = epoch;
    out.nodeCount = out.edgeCount = 0;
    out.startNode = 0;
    out.goalNode = ~0u;
    out.excludedAreas = out.clippedEdges = 0;
    out.spaceIdentity = 0;
    __builtin_memset(out.identityLookup, 0, sizeof(out.identityLookup));
    const uint8_t *first = Area(start), *last = Area(goal);
    if (!first || !last || !start.space || !goal.space || !nodeLimit || !edgeLimit)
        return NavGraphResult::InvalidHandle;
    if (start.space != goal.space)
        return NavGraphResult::DifferentSpace;
    if (!Supported(first, spec) || !Supported(last, spec))
        return NavGraphResult::UnsupportedArea;
    out.spaceIdentity = reinterpret_cast<uint64_t>(start.space);
    __builtin_memcpy(out.spaceTransform, static_cast<const uint8_t *>(start.space) + 76,
                     sizeof(out.spaceTransform));
    out.specification = spec;
    if (nodeLimit > NavGraphMaxNodes)
        nodeLimit = NavGraphMaxNodes;
    if (edgeLimit > NavGraphMaxEdges)
        edgeLimit = NavGraphMaxEdges;
    // Borrowed pointers exist only in this synchronous stack scope; none escape.
    const uint8_t *areas[NavGraphMaxNodes];
    areas[0] = first;
    out.nodeCount = 1;
    Insert(out, 0, reinterpret_cast<uint64_t>(first));
    for (uint32_t n = 0; n < out.nodeCount; ++n)
    {
        const uint8_t *area = areas[n];
        auto &node = out.nodes[n];
        node.position = World(start.space, Read<Vec3>(area, 32));
        node.firstEdge = out.edgeCount;
        node.edgeCount = 0;
        if (!Finite(node.position))
            return NavGraphResult::InvalidGeometry;
        if (area == last)
            out.goalNode = n;
        const uint32_t count = Read<uint32_t>(area, 56) & 127u;
        for (uint32_t e = 0; e < count; ++e)
        {
            const uint8_t *next = Read<const uint8_t *>(area, 72 + 32 * e);
            if (!next)
                continue;
            if (!Supported(next, spec))
            {
                ++out.excludedAreas;
                continue;
            }
            uint32_t id = Lookup(out, reinterpret_cast<uint64_t>(next));
            if ((id == ~0u && out.nodeCount == nodeLimit) || out.edgeCount == edgeLimit)
            {
                ++out.clippedEdges;
                continue;
            }
            const Vec3 a = World(start.space, Read<Vec3>(area, 80 + 32 * e));
            const Vec3 b = World(start.space, Read<Vec3>(area, 80 + 32 * ((e + 1) % count)));
            const Vec3 portal{(a.x + b.x) * 0.5f, (a.y + b.y) * 0.5f, (a.z + b.z) * 0.5f};
            const Vec3 center = World(start.space, Read<Vec3>(next, 32));
            const float cost = Distance(node.position, portal) + Distance(portal, center);
            if (!Finite(a) || !Finite(b) || !Finite(center) || !__builtin_isfinite(cost))
                return NavGraphResult::InvalidGeometry;
            if (id == ~0u)
            {
                id = out.nodeCount++;
                areas[id] = next;
                Insert(out, id, reinterpret_cast<uint64_t>(next));
            }
            out.edges[out.edgeCount++] = {id, cost > 0.001f ? cost : 0.001f, portal};
            ++node.edgeCount;
        }
    }
    return out.goalNode == ~0u ? NavGraphResult::GoalOutsidePartition : NavGraphResult::Ready;
}
} // namespace HostScale
