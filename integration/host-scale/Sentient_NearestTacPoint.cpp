#include "sv_host_navigation.h"

namespace
{
    struct SentientNavigationView
    {
        HostScale::Entity *entity;
        void *ai;
        uint8_t opaque16[96];
        void *nearestNode;
        uint8_t opaque120[28];
        uint8_t tacticalReference[4];
        uint8_t tacticalValid, tacticalWithoutLos;
        uint8_t opaque154[30];
    };
    static_assert(offsetof(SentientNavigationView, nearestNode) == 112);
    static_assert(offsetof(SentientNavigationView, tacticalReference) == 148);
    static_assert(offsetof(SentientNavigationView, tacticalValid) == 152);
    static_assert(sizeof(SentientNavigationView) == 184);

    struct FailedLookup
    {
        void *sentient, *player, *node, *ai;
        HostScale::Vec3 origin;
        int32_t time, graphs;
        bool valid;
    };
    FailedLookup s_failed[200]{};
}

extern "C" void *Sentient_NearestTacPoint(void *data)
{
    using namespace HostScale;
    auto *sentient = static_cast<SentientNavigationView *>(data);
    // An empty tactical asset cannot produce a point. Do not first search the
    // entire navigation mesh to prove that fact for every bot on every tick.
    // Recheck the count on every call so loading a graph restores native lookup.
    if (Enabled() && SVHS_TacGraphCount <= 0)
    {
        SVHS_TacSetReference(sentient->tacticalReference, nullptr);
        sentient->tacticalValid = 0;
        sentient->tacticalWithoutLos = 1;
        return nullptr;
    }
    if (sentient->tacticalValid)
        return SVHS_TacGetReference(sentient->tacticalReference);

    // Failed point searches have no native cache. Most Verdansk bots observed
    // outside tactical coverage repeat them indefinitely. Cache absence briefly
    // within the serialized bot scope; no resource/point handle is retained.
    FailedLookup *failed = nullptr;
    if (Enabled() && SV_HostNav_OwnsBotScope() && sentient->entity)
    {
        const unsigned slot = uint16_t(sentient->entity->number);
        if (slot < 200)
        {
            failed = &s_failed[slot];
            const auto &origin = sentient->entity->origin;
            const float x = origin.x - failed->origin.x, y = origin.y - failed->origin.y,
                        z = origin.z - failed->origin.z;
            if (failed->valid && failed->sentient == sentient && failed->player == sentient->entity->client &&
                failed->node == sentient->nearestNode && failed->ai == sentient->ai &&
                failed->graphs == SVHS_TacGraphCount && SVHS_LevelTime >= failed->time &&
                SVHS_LevelTime - failed->time < 250 && x * x + y * y + z * z < 64.0f * 64.0f)
                return nullptr;
        }
    }

    void *point = nullptr;
    if (sentient->nearestNode)
    {
        Vec3 position{};
        SVHS_PathNodePosition(sentient->nearestNode, &position);
        const auto &origin = sentient->entity->origin;
        const float x = origin.x - position.x, y = origin.y - position.y, z = origin.z - position.z;
        if (!((y * y + x * x) + z * z >= 2304.0f))
            point = SVHS_TacPointForNode(sentient->nearestNode);
    }
    if (!point && sentient->ai)
    {
        void *navigator = Field<void *>(sentient->ai, 360);
        if (navigator)
        {
            const auto *vtable = Field<const uintptr_t *>(navigator, 0);
            point = reinterpret_cast<void *(*)(void *)>(vtable[48])(navigator);
        }
    }
    if (!point)
    {
        NavAreaHandle area{};
        SVHS_NavConstructArea(&area);
        Vec3 snapped{};
        SVHS_NavClosestVerticalDefault(&sentient->entity->origin, &snapped, &area);
        point = SVHS_TacClosestWithLos(&sentient->entity->origin, &snapped, &area);
        SVHS_NavDestroyArea(&area);
    }
    sentient->tacticalWithoutLos = point ? 0 : 1;
    if (!point)
        point = SVHS_TacClosest(&sentient->entity->origin);
    SVHS_TacSetReference(sentient->tacticalReference, point);
    sentient->tacticalValid = point != nullptr;
    if (failed)
        *failed = {sentient, sentient->entity->client, sentient->nearestNode, sentient->ai,
                   sentient->entity->origin, SVHS_LevelTime, SVHS_TacGraphCount, point == nullptr};
    return SVHS_TacGetReference(sentient->tacticalReference);
}
