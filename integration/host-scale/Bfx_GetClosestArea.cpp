#include "sv_host_navigation.h"

namespace
{
    struct AreaResults
    {
        void **items;
        int32_t count, capacity;
        uint32_t allocationFlags;
    };
    static_assert(sizeof(AreaResults) == 24 && offsetof(AreaResults, allocationFlags) == 16);

    void Release(AreaResults &results)
    {
        using namespace HostScale;
        if (!results.items || (results.allocationFlags & 0x100))
            return;
        void *manager = Field<void *>(SVHS_NavSystem, 8);
        if (Field<uint32_t>(manager, 60))
            SVHS_NavFree(manager, results.items);
        else
        {
            void *allocator = Field<void *>(manager, 16);
            const auto *vtable = Field<const uintptr_t *>(allocator, 0);
            reinterpret_cast<void (*)(void *, void *)>(vtable[2])(allocator, results.items);
        }
    }
}

extern "C" void *Bfx_GetClosestArea(void *planner, const void *position,
                                    unsigned layerIndex, const void *specification)
{
    using namespace HostScale;
    if (layerIndex >= 32)
        return nullptr;
    void *layer = Field<void *>(planner, 32 + 8 * layerIndex);
    if (!layer)
        return nullptr;
    const bool optimized = Enabled();
    AreaResults results{nullptr, 0, 0, uint8_t(SVHS_NavAllocationTag)};
    SVHS_NavGetClosestAreas(layer, position, specification,
        optimized ? 1024.0f : SVHS_NavUnlimitedRadius, 1, &results);
    bool fallback = false;
    if (optimized && results.count == 0)
    {
        // Only a bot-owned scope receives a bounded fallback. Nested searches
        // restore the outer stack-owned budget; no graph pointer is cached.
        Release(results);
        results = {nullptr, 0, 0, uint8_t(SVHS_NavAllocationTag)};
        NavClosestBudget budget{};
        auto *previous = SV_HostNav_SetClosestBudget(&budget);
        SVHS_NavGetClosestAreas(layer, position, specification, SVHS_NavUnlimitedRadius, 1, &results);
        SV_HostNav_SetClosestBudget(previous);
        SV_HostNav_RecordClosestBudget(&budget);
        fallback = true;
    }
    void *closest = results.count ? results.items[0] : nullptr;
    Release(results);
    if (optimized)
        SV_HostNav_RecordClosest(fallback);
    return closest;
}
