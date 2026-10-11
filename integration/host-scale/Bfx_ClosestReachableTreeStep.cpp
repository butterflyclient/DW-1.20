#include "sv_host_navigation.h"

extern "C" unsigned Bfx_ClosestReachableTreeStep(HostScale::NavTreeWalk *walk, int count)
{
    using namespace HostScale;
    int remaining = count;
    while (walk->top > walk->stack)
    {
        if (remaining <= 0 || !SV_HostNav_SpatialWork())
            break;
        const NavTreeEntry item = *--walk->top;
        --remaining;
        const float maximum = Field<float>(walk->collector, 8);
        if (!(item.distance < maximum))
            continue;
        auto *node = item.node;
        const int32_t type = Field<int32_t>(node, 0);
        if (type >= 0)
        {
            const unsigned axis = (uint32_t(type) >> 28) & 7;
            const float coordinate = reinterpret_cast<float *>(walk)[axis];
            float rightDistance = Field<float>(node, 8) - coordinate;
            float leftDistance = coordinate - Field<float>(node, 4);
            uint8_t *left = node + 12;
            uint8_t *right = node + (uint32_t(type) & 0x0fffffff);
            // Preserve native traversal/tie order and floating-point comparisons.
            if (leftDistance <= rightDistance)
            {
                if (rightDistance < maximum)
                {
                    if (item.distance - rightDistance >= 0.0f)
                        rightDistance = item.distance;
                    walk->top->node = right;
                    walk->top++->distance = rightDistance;
                }
                if (leftDistance >= maximum)
                    continue;
                walk->top->node = left;
                walk->top++->distance = item.distance - leftDistance < 0.0f ? leftDistance : item.distance;
            }
            else
            {
                if (leftDistance < maximum)
                {
                    if (item.distance - leftDistance >= 0.0f)
                        leftDistance = item.distance;
                    walk->top->node = left;
                    walk->top++->distance = leftDistance;
                }
                if (rightDistance >= maximum)
                    continue;
                walk->top->node = right;
                walk->top++->distance = item.distance - rightDistance < 0.0f ? rightDistance : item.distance;
            }
        }
        else
        {
            auto *resource = Field<uint8_t *>(walk->collector, 56);
            auto *area = Field<uint8_t *>(resource, 24) + (uint32_t(type) & 0x7fffffff);
            auto *children = Field<uint8_t *>(area, 8);
            if (children && Field<uint32_t>(children, 0))
            {
                const unsigned total = Field<uint32_t>(children, 0);
                auto *child = children + 28;
                for (unsigned i = 0; i < total && SV_HostNav_SpatialWork(); ++i)
                {
                    SVHS_NavCollectArea(walk->collector, child, &walk->point);
                    child += 96 + 32 * (Field<uint32_t>(child, 56) & 127);
                }
            }
            else
                SVHS_NavCollectArea(walk->collector, area, &walk->point);
        }
    }
    return unsigned(count - remaining);
}
