#include "sv_host_navigation.h"
#include <xmmintrin.h>

namespace
{
    using namespace HostScale;

    bool Usable(const NavClosestCollector *collector, const NavClosestAreaView *area)
    {
        const auto &spec = *collector->spec;
        if (area->shapeFlags & 0x20000000)
        {
            const uint32_t matched = spec.obstacleFlags & area->obstacleFlags;
            if (spec.obstacleMode ? matched == spec.obstacleFlags : matched != 0)
                return false;
        }
        return !area->areaFlags || (area->areaFlags & spec.areaFlags);
    }
}

extern "C" void Bfx_ClosestAreaCollect(HostScale::NavClosestCollector *collector,
                                       HostScale::NavClosestAreaView *area, const HostScale::Vec3 *point)
{
    using namespace HostScale;
    const bool optimized = Enabled();
    if (optimized && collector->spec && !Usable(collector, area))
        return;
    const float x = point->x - area->center.x;
    const float y = point->y - area->center.y;
    const float z = point->z - area->center.z;
    const float radius = area->radius + collector->maximumDistance;
    if ((y * y + x * x) + z * z > radius * radius)
        return;
    if ((!optimized || !collector->spec) && !Usable(collector, area))
        return;
    Vec3 projected = area->center;
    SVHS_NavProjectClosest(&projected, area, point, nullptr);
    const float px = projected.x - point->x;
    const float py = projected.y - point->y;
    const float pz = projected.z - point->z;
    const float distance = _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss((py * py + px * px) + pz * pz)));
    if (distance > collector->maximumDistance)
        return;
    void *reference = area;
    SVHS_NavInsertClosest(&collector->areas, &reference, distance);
    if (collector->areas.count == collector->desiredCount)
    {
        float farthest = SVHS_NavFarthestClosest(&collector->areas);
        if (!(collector->maximumDistance - farthest >= 0.0f))
            farthest = collector->maximumDistance;
        collector->maximumDistance = farthest;
    }
}
