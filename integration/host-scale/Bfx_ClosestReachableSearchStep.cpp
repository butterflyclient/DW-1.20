#include "sv_host_navigation.h"

namespace
{
    void NextArea(HostScale::NavSearchStep *step)
    {
        using namespace HostScale;
        ++step->areaIndex;
        step->subArea = nullptr;
        step->subCount = step->subIndex = 0;
        if (step->areaIndex < step->looseAreas->count)
        {
            auto *children = Field<uint8_t *>(step->looseAreas->areas[step->areaIndex], 8);
            if (children && Field<int32_t>(children, 0) > 0)
            {
                step->subArea = children + 28;
                step->subCount = Field<int32_t>(children, 0);
            }
        }
    }
}

extern "C" unsigned Bfx_ClosestReachableSearchStep(HostScale::NavSearchStep *step, int count)
{
    using namespace HostScale;
    Field<void *>(step->collector, 56) = step->resource;
    int remaining = count;
    if (step->tree.top != step->tree.stack)
        remaining -= int(Bfx_ClosestReachableTreeStep(&step->tree, count));
    while (step->areaIndex < step->looseAreas->count)
    {
        if (remaining <= 0 || !SV_HostNav_SpatialWork())
            break;
        auto *area = step->looseAreas->areas[step->areaIndex];
        auto *children = Field<uint8_t *>(area, 8);
        SVHS_NavCollectArea(step->collector,
            children && Field<int32_t>(children, 0) ? step->subArea : area, step->point);
        // The collector can mutate the native list, so reload it after the call.
        children = Field<uint8_t *>(step->looseAreas->areas[step->areaIndex], 8);
        if (children && Field<int32_t>(children, 0))
        {
            step->subArea += 96 + 32 * (Field<uint32_t>(step->subArea, 56) & 127);
            if (++step->subIndex == step->subCount)
                NextArea(step);
        }
        else
            NextArea(step);
        --remaining;
    }
    return unsigned(count - remaining);
}
