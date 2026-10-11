#include "sv_host_navigation.h"

namespace
{
    void Grow(HostScale::NavReachQueue *queue)
    {
        using namespace HostScale;
        const size_t used = queue->write - queue->storage;
        queue->capacity *= 2;
        const size_t bytes = queue->capacity * sizeof(NavIsland *);
        void *manager = Field<void *>(SVHS_NavSystem, 8);
        NavIsland **replacement;
        if (Field<uint32_t>(manager, 60))
            replacement = static_cast<NavIsland **>(
                SVHS_NavMalloc(manager, bytes, SVHS_NavAllocationTag, 8));
        else
        {
            void *allocator = Field<void *>(manager, 16);
            const auto *vtable = Field<const uintptr_t *>(allocator, 0);
            replacement = static_cast<NavIsland **>(
                reinterpret_cast<void *(*)(void *, uint32_t)>(vtable[0])(allocator, uint32_t(bytes)));
        }
        if (!replacement && bytes)
        {
            auto failure = Field<void (*)()>(manager, 32);
            if (failure)
                failure();
            else
                SVHS_NavAllocationFailure();
        }
        SVHS_NavMemmove(replacement, queue->storage, used * sizeof(NavIsland *));
        // Compute offsets before freeing the old queue; no dangling subtraction.
        const size_t readOffset = queue->read - queue->storage;
        manager = Field<void *>(SVHS_NavSystem, 8);
        if (Field<uint32_t>(manager, 60))
            SVHS_NavFree(manager, queue->storage);
        else
        {
            void *allocator = Field<void *>(manager, 16);
            const auto *vtable = Field<const uintptr_t *>(allocator, 0);
            reinterpret_cast<void (*)(void *, void *)>(vtable[2])(allocator, queue->storage);
        }
        queue->storage = replacement;
        queue->read = replacement + readOffset;
        queue->write = replacement + used;
    }
}

extern "C" void Bfx_IncrementalSearchToIsland(HostScale::NavIncrementalSearch *search, int island)
{
    using namespace HostScale;
    auto *queue = search->queue;
    if (!queue)
        return;
    auto *target = (*search->islands)[island];
    while (queue->read != queue->write)
    {
        auto *current = *queue->read;
        if (current == target || !SV_HostNav_HasWork())
            return;
        ++queue->read;
        for (int i = 0; i < current->edgeCount; ++i)
        {
            if (!SV_HostNav_GraphWork())
                return;
            const auto &edge = current->edges[i];
            auto *next = edge.destination;
            if (next->visited == *queue->generation)
                continue;
            const auto &spec = *queue->spec;
            const uint32_t blocked = spec.obstacleFlags & next->obstacleFlags;
            if (spec.obstacleMode ? blocked == spec.obstacleFlags : blocked != 0)
                continue;
            if (next->areaFlags && !(next->areaFlags & spec.areaFlags))
                continue;
            if (!edge.open && !(edge.linkFlags & spec.linkFlags))
                continue;
            *queue->write++ = next;
            next->visited = *queue->generation;
            if (size_t(queue->write - queue->storage) >= queue->capacity)
                Grow(queue);
        }
        queue = search->queue;
    }
}
