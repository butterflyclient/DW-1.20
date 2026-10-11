#include "sv_host_navigation.h"

namespace
{
    using namespace HostScale;

    bool CannotImprove(const Vec3 &bounds, const Vec3 &localPoint, const Vec3 &point, float maximum)
    {
        // The native walker retains only the largest axis separation. Three
        // independent KD half-space bounds also give a Euclidean lower bound.
        // Leave a generous float-rounding margin around the decision boundary.
        const double x = bounds.x, y = bounds.y, z = bounds.z;
        const double radius = maximum;
        const double magnitude = __builtin_fabs(double(point.x)) + __builtin_fabs(double(point.y)) +
                                 __builtin_fabs(double(point.z)) + __builtin_fabs(double(localPoint.x)) +
                                 __builtin_fabs(double(localPoint.y)) + __builtin_fabs(double(localPoint.z)) +
                                 radius + x + y + z;
        const double margin = magnitude * (64.0 * 1.1920928955078125e-7) + 0.01;
        const double relaxed = radius + margin;
        return x * x + y * y + z * z > relaxed * relaxed;
    }
}

extern "C" unsigned Bfx_ClosestAreaTreeStep(HostScale::NavTreeWalk *walk, int count)
{
    using namespace HostScale;
    if (count <= 0 || walk->top <= walk->stack)
        return 0;
    const bool tighten = Enabled() && Field<float>(walk->collector, 8) > 2048.0f;
    auto *budget = SV_HostNav_GetClosestBudget();
    Vec3 bounds[256];
    if (tighten)
        __builtin_memset(bounds, 0, sizeof(bounds));
    int remaining = count;
    while (walk->top > walk->stack)
    {
        if (remaining <= 0)
            break;
        if (!ClosestWork(budget, Field<int32_t>(walk->collector, 24) != 0))
        {
            // This native traversal is synchronous. Empty its pending stack so
            // an outer driver cannot repeatedly resume an exhausted query.
            walk->top = walk->stack;
            break;
        }
        const NavTreeEntry item = *--walk->top;
        --remaining;
        const ptrdiff_t depth = walk->top - walk->stack;
        const float maximum = Field<float>(walk->collector, 8);
        if (!(item.distance < maximum))
            continue;
        Vec3 inherited{};
        if (tighten && depth >= 0 && depth < 256)
        {
            inherited = bounds[depth];
            if (CannotImprove(inherited, walk->localPoint, walk->point, maximum))
                continue;
        }
        auto push = [&](uint8_t *node, unsigned axis, float separation)
        {
            const ptrdiff_t at = walk->top - walk->stack;
            if (tighten && at >= 0 && at < 256)
            {
                bounds[at] = inherited;
                if (axis < 3)
                {
                    auto *components = reinterpret_cast<float *>(&bounds[at]);
                    if (separation > components[axis])
                        components[axis] = separation;
                }
            }
            walk->top->node = node;
            walk->top++->distance = item.distance - separation < 0.0f ? separation : item.distance;
        };
        auto *node = item.node;
        const int32_t type = Field<int32_t>(node, 0);
        if (type >= 0)
        {
            const unsigned axis = (uint32_t(type) >> 28) & 7;
            const float coordinate = reinterpret_cast<float *>(walk)[axis];
            const float rightDistance = Field<float>(node, 8) - coordinate;
            const float leftDistance = coordinate - Field<float>(node, 4);
            uint8_t *left = node + 12;
            uint8_t *right = node + (uint32_t(type) & 0x0fffffff);
            if (leftDistance <= rightDistance)
            {
                if (rightDistance < maximum)
                    push(right, axis, rightDistance);
                if (!(leftDistance >= maximum))
                    push(left, axis, leftDistance);
            }
            else
            {
                if (leftDistance < maximum)
                    push(left, axis, leftDistance);
                if (!(rightDistance >= maximum))
                    push(right, axis, rightDistance);
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
                for (unsigned i = 0; i < total; ++i)
                {
                    if (budget && budget->exhausted)
                        break;
                    SVHS_NavCollectClosest(walk->collector, child, &walk->point);
                    child += 96 + 32 * (Field<uint32_t>(child, 56) & 127);
                }
            }
            else
                SVHS_NavCollectClosest(walk->collector, area, &walk->point);
        }
    }
    return unsigned(count - remaining);
}
