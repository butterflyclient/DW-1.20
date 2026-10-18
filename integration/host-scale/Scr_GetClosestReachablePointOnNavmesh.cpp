#include "sv_host_navigation.h"
#include "sv_host_bot_equipment.h"

namespace
{
    using namespace HostScale;
    struct CachedGoal
    {
        void *navigator, *area, *space, *client;
        Vec3 requested, result;
        uint64_t configuration;
        int32_t time;
        bool valid;
    };
    CachedGoal s_goals[200]{};

    uint64_t Configuration(const Nav2DQueryView *navigator)
    {
        uint64_t hash = 14695981039346656037ull;
        for (uint8_t byte : navigator->pathConfiguration)
            hash = (hash ^ byte) * 1099511628211ull;
        return hash;
    }

    bool Valid(const NavAreaHandle &area)
    {
        return area.reference && *area.reference && area.space;
    }

    bool NearbyRequest(const Vec3 &a, const Vec3 &b)
    {
        const float x = a.x - b.x, y = a.y - b.y, z = a.z - b.z;
        return x * x + y * y + z * z <= 128.0f * 128.0f;
    }

    void Native(void *navigator, const Vec3 &requested, Vec3 &result)
    {
        const auto *vtable = Field<const uintptr_t *>(navigator, 0);
        reinterpret_cast<void (*)(void *, const Vec3 *, Vec3 *)>(vtable[45])(
            navigator, &requested, &result);
    }
}

extern "C" void Scr_GetClosestReachablePointOnNavmesh(void *context, uint32_t reference)
{
    using namespace HostScale;
    auto *entity = static_cast<Entity *>(SVHS_ScriptEntity(reference));
    if (!entity)
        SVHS_ScriptError(5789, context, "GetClosestReachablePointOnNavmesh : invalid entity.");
    void *navigator = SVHS_Navigator(entity);
    if (!navigator)
        SVHS_ScriptError(5790, context, SVHS_NavFormat(
            "GetClosestReachablePointOnNavmesh : Entity %d does not have a navigator.", entity->number));
    Vec3 requested{}, result{};
    SVHS_ScriptGetVector(context, 0, &requested);
    const unsigned population = Enabled() ? Population() : 0;
    const unsigned slot = uint16_t(entity->number);
    auto *view = static_cast<Nav2DQueryView *>(navigator);
    // Gulag's normal fight script requests a reachable opponent goal only every
    // three seconds. Frame admission can repeatedly miss that query and return
    // a projection onto the fighter's own area, leaving its guard goal at spawn.
    // Preserve the complete native query for jail/arena transitions and fights.
    const auto *player = reinterpret_cast<const BotEquipmentPlayer *>(entity->client);
    const bool gulag = player && (player->gameExtraInfo & 0x600);
    if (gulag || population <= 20 || slot >= 200 || !SVHS_IsBotEntity(entity) ||
        view->vtable[45] != reinterpret_cast<uintptr_t>(&SVHS_Nav2DClosest) || !Valid(view->currentArea))
    {
        if (slot < 200)
            s_goals[slot].valid = false;
        Native(navigator, requested, result);
        SVHS_ScriptAddVector(context, &result);
        return;
    }
    unsigned ordinal = 0;
    for (unsigned i = 0; i < slot && i < SVHS_ClientCount; ++i)
        if (SVHS_Clients[i] && Field<uint8_t>(SVHS_Clients[i], 8) >= 3)
            ++ordinal;
    const unsigned scope = SV_HostNav_Begin(ordinal, population);
    if (!scope)
    {
        Native(navigator, requested, result);
        SVHS_ScriptAddVector(context, &result);
        return;
    }
    auto &cached = s_goals[slot];
    const int32_t now = SVHS_LevelTime;
    const uint64_t configuration = Configuration(view);
    void *area = *view->currentArea.reference;
    const bool reusable = cached.valid && cached.navigator == navigator && cached.area == area &&
        cached.space == view->currentArea.space && cached.client == entity->client &&
        cached.configuration == configuration && now >= cached.time && now - cached.time < 750 &&
        NearbyRequest(cached.requested, requested);
    unsigned outcome = 0;
    if (reusable)
    {
        result = cached.result;
        outcome = 2;
    }
    else
    {
        NavAreaHandle chosen{};
        if (scope == 1)
            SVHS_NavClosestArea(&chosen, &requested, &view->currentArea, view->pathConfiguration);
        const bool found = Valid(chosen);
        // Projection onto the current valid area is reachable by construction.
        // Never manufacture a graph connection or project through unloaded data.
        SVHS_NavProjectArea(found ? &chosen : &view->currentArea, &result, &requested, nullptr);
        SVHS_NavDestroyArea(&chosen);
        outcome = found ? 0 : 1;
        if (found)
            cached = {navigator, area, view->currentArea.space, entity->client,
                      requested, result, configuration, now, true};
    }
    SV_HostNav_End(outcome);
    SVHS_ScriptAddVector(context, &result);
}
