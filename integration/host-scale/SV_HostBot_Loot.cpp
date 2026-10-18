#include "sv_host_bot_loot.h"
#include "SV_HostBotLootBindings.h"
#include <intrin.h>

namespace
{
    using namespace HostScale;

    struct BotLootView
    {
        Entity *entity;
        Sentient *sentient;
        uint8_t opaque16[432];
        uint8_t *playerState;
        uint8_t opaque456[164];
        int32_t traversal;
        uint8_t opaque624[8360];
        uint32_t scriptFlags;
        uint8_t opaque8988[19204];
        BotLootLookRequest look;
    };

    static_assert(offsetof(BotLootView, playerState) == 448);
    static_assert(offsetof(BotLootView, traversal) == 620);
    static_assert(offsetof(BotLootView, scriptFlags) == 8984);
    static_assert(offsetof(BotLootView, look) == 28192);

    struct Attempt
    {
        uint32_t index, generation;
        int32_t time;
        bool valid;
    };

    struct LootState
    {
        void *owner, *player, *mapStatics;
        Vec3 origin, goal;
        int32_t lastTime, nextScan, goalTime;
        uint32_t index, generation;
        Attempt attempts[8];
        unsigned nextAttempt;
        bool valid;
    };

    LootState s_states[200]{};
    int32_t s_scanTime = -1;
    unsigned s_scans;

    BotGasState s_gas{};
    void *s_gasStatics;
    uint32_t s_gasGeneration;
    struct GasGoal
    {
        void *owner, *player;
        Vec3 goal, center;
        float radius;
        int32_t lastTime;
        uint32_t generation;
        bool valid;
    };
    GasGoal s_gasGoals[200]{};

    bool Finite(const Vec3 &v)
    {
        return __builtin_isfinite(v.x) && __builtin_isfinite(v.y) && __builtin_isfinite(v.z);
    }

    bool GasEligible(const BotLootView *bot)
    {
        // Evacuation remains eligible during native combat; loot's CanFire
        // exclusion must never make a threatened bot ignore the circle.
        return bot && bot->entity && bot->entity->client && bot->sentient &&
               bot->entity->health > 0 && bot->playerState && !bot->traversal &&
               unsigned(uint16_t(bot->entity->number)) < 200 &&
               !(Field<uint32_t>(bot->entity->client, 22336) & 0x600) &&
               Field<uint32_t>(bot->playerState, 12) <= 1 &&
               !(Field<uint32_t>(bot->playerState, 28) & 0x800) &&
               !SVHBL_IsSkydiving(bot->playerState) &&
               Field<int32_t>(bot->playerState, 0) >= Field<int32_t>(bot->playerState, 4) &&
               !(bot->scriptFlags & 4) && !(Field<uint8_t>(bot->playerState, 24) & 1) &&
               !(Field<uint32_t>(bot->playerState, 364) & 0xe0) &&
               Field<uint16_t>(bot->playerState, 626) != 2047 && Finite(bot->entity->origin);
    }

    float GasDistanceSquared(const Vec3 &a, const Vec3 &b)
    {
        const float x = a.x - b.x, y = a.y - b.y;
        return x * x + y * y;
    }

    float GasMarginRadius(float radius)
    {
        return radius > 256.0f ? radius - 128.0f : radius * 0.5f;
    }

    struct GameStaticsScope
    {
        void **slot;
        void *previous;

        GameStaticsScope()
        {
#if defined(SVHBL_TESTING)
            extern void **SVHBL_TestGameStaticsSlot();
            slot = SVHBL_TestGameStaticsSlot();
#else
            auto *slots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
            slot = reinterpret_cast<void **>(slots[SVHS_BotTlsIndex] + 16);
#endif
            previous = *slot;
            *slot = SVHS_GameStatics;
        }

        ~GameStaticsScope()
        {
            *slot = previous;
        }
    };

    float DistanceSquared(const Vec3 &a, const Vec3 &b)
    {
        const float x = a.x - b.x, y = a.y - b.y, z = a.z - b.z;
        return x * x + y * y + z * z;
    }

    bool Prefix(const char *text, const char *prefix)
    {
        if (!text)
            return false;
        while (*prefix)
            if (*text++ != *prefix++)
                return false;
        return true;
    }

    bool Equal(const char *a, const char *b)
    {
        if (!a)
            return false;
        while (*a && *a == *b)
        {
            ++a;
            ++b;
        }
        return *a == *b;
    }

    bool Eligible(const BotLootView *bot)
    {
        return bot && bot->entity && bot->entity->client && bot->sentient &&
               bot->entity->health > 0 && bot->playerState && !bot->traversal &&
               !(Field<uint32_t>(bot->entity->client, 22336) & 0x600) && // BR Gulag jail/arena.
               Field<uint32_t>(bot->playerState, 12) <= 1 &&       // PM_NORMAL / PM_NORMAL_LINKED.
               !(Field<uint32_t>(bot->playerState, 28) & 0x800) && // LASTSTAND.
               !SVHBL_IsSkydiving(bot->playerState) &&
               Field<int32_t>(bot->playerState, 0) >= Field<int32_t>(bot->playerState, 4) &&
               !(bot->scriptFlags & 4) && !(Field<uint8_t>(bot->playerState, 24) & 1) &&
               !(Field<uint32_t>(bot->playerState, 364) & 0xe0) &&
               Field<uint16_t>(bot->playerState, 626) != 2047 &&
               !SVHS_BotCanFire(const_cast<BotLootView *>(bot));
    }

    unsigned Slot(const BotLootView *bot)
    {
        return unsigned(uint16_t(bot->entity->number));
    }

    bool Owned(const BotLootView *bot, const LootState &state, int32_t now)
    {
        return state.owner == bot && state.player == bot->playerState &&
               state.mapStatics == SVHS_GameStatics && now >= state.lastTime &&
               DistanceSquared(state.origin, bot->entity->origin) < 1024.0f * 1024.0f;
    }

    int Score(const LootItemDefinition *item, bool needsWeapon)
    {
        if (!item || !item->name)
            return 0;
        const char *name = item->name;
        if (Prefix(name, "brloot_weapon_"))
        {
            if (!needsWeapon || Equal(name, "brloot_weapon_generic_me") ||
                Equal(name, "brloot_weapon_generic_kn"))
                return 0;
            return 100 + (item->rarity <= 4 ? item->rarity : 0);
        }
        // Quest caches and mission items are left to their native objectives.
        if (Equal(name, "br_loot_cache") || Equal(name, "br_loot_cache_lege"))
            return needsWeapon ? 90 : 40;
        if (Equal(name, "brloot_armor_plate") || Equal(name, "brloot_plate_pouch"))
            return 70;
        if (Equal(name, "brloot_equip_gasmask") || Equal(name, "brloot_self_revive"))
            return 60;
        if (Prefix(name, "brloot_ammo_") && !Equal(name, "brloot_ammo_grenade"))
            return 50;
        return 0;
    }

    bool RecentlyAttempted(const LootState &state, uint32_t index, uint32_t generation, int32_t now)
    {
        for (const auto &attempt : state.attempts)
            if (attempt.valid && attempt.index == index && attempt.generation == generation &&
                now >= attempt.time && now - attempt.time < 8000)
                return true;
        return false;
    }
} // namespace

extern "C" void SV_HostBot_ResetGasState()
{
    s_gas = {};
    s_gasStatics = nullptr;
    ++s_gasGeneration;
    for (auto &goal : s_gasGoals)
        goal = {};
}

extern "C" bool SV_HostBot_PublishGasState(const HostScale::BotGasState *sample)
{
    if (!sample || !HostScale::Enabled() || !sample->valid ||
        !Finite(sample->currentCenter) || !Finite(sample->nextCenter) ||
        !__builtin_isfinite(sample->currentRadius) || !__builtin_isfinite(sample->nextRadius) ||
        sample->currentRadius <= 0 || sample->nextRadius <= 0)
    {
        SV_HostBot_ResetGasState();
        return false;
    }
    if (s_gasStatics != SVHS_GameStatics ||
        SVHS_LevelTime < s_gas.sampledTime)
        SV_HostBot_ResetGasState();
    s_gas = *sample;
    s_gas.sampledTime = SVHS_LevelTime;
    s_gas.generation = s_gasGeneration;
    s_gasStatics = SVHS_GameStatics;
    return true;
}

extern "C" bool SV_HostBot_GetGasState(HostScale::BotGasState *out)
{
    if (!out || !HostScale::Enabled() || !s_gas.valid ||
        s_gasStatics != SVHS_GameStatics ||
        SVHS_LevelTime < s_gas.sampledTime ||
        SVHS_LevelTime - s_gas.sampledTime > 2000)
        return false;
    *out = s_gas;
    return true;
}

extern "C" bool SV_HostBot_GasEvacuationRequired(void *data)
{
    const auto *bot = static_cast<const BotLootView *>(data);
    HostScale::BotGasState gas{};
    if (!GasEligible(bot) || !SV_HostBot_GetGasState(&gas))
        return false;
    const auto &center = gas.closing ? gas.nextCenter : gas.currentCenter;
    const float radius = GasMarginRadius(gas.closing ? gas.nextRadius : gas.currentRadius);
    return GasDistanceSquared(bot->entity->origin, center) > radius * radius;
}

extern "C" bool SV_HostBot_GetGasGoal(void *data, HostScale::Vec3 *out)
{
    const auto *bot = static_cast<const BotLootView *>(data);
    HostScale::BotGasState gas{};
    if (!out || !SV_HostBot_GasEvacuationRequired(data) || !SV_HostBot_GetGasState(&gas))
        return false;
    const auto &center = gas.closing ? gas.nextCenter : gas.currentCenter;
    const float radius = GasMarginRadius(gas.closing ? gas.nextRadius : gas.currentRadius);
    auto &state = s_gasGoals[unsigned(uint16_t(bot->entity->number))];
    if (!state.valid || state.owner != bot || state.player != bot->playerState ||
        state.generation != gas.generation || SVHS_LevelTime < state.lastTime ||
        GasDistanceSquared(state.goal, center) > radius * radius ||
        GasDistanceSquared(state.center, center) > 128.0f * 128.0f || state.radius != radius)
    {
        // Use the same evacuation destination until the circle changes. Keep
        // current elevation for native projection; circle Z is not a floor.
        // The central destination provides slack if boundary projection fails.
        state = {const_cast<BotLootView *>(bot), bot->playerState,
                 {center.x, center.y, bot->entity->origin.z}, center, radius,
                 SVHS_LevelTime, gas.generation, true};
    }
    state.lastTime = SVHS_LevelTime;
    *out = state.goal;
    return true;
}

extern "C" bool SV_HostBot_AllowSurvival(void *data)
{
    auto *bot = static_cast<BotLootView *>(data);
    GameStaticsScope gameStatics;
    return Enabled() && Eligible(bot) && !bot->sentient->targetHandle &&
           !SV_HostBot_GasEvacuationRequired(data);
}

extern "C" void SV_HostBot_UpdateLoot(void *data, HostScale::UserCmd *command)
{
    using namespace HostScale;
    (void)command; // Movement/look consume GetLootGoal through the normal bot path.
    auto *bot = static_cast<BotLootView *>(data);
    GameStaticsScope gameStatics;
    if (!Enabled() || !Eligible(bot) || SV_HostBot_GasEvacuationRequired(data))
        return;
    const unsigned slot = Slot(bot);
    if (slot >= 200)
        return;
    const int32_t now = SVHS_LevelTime;
    auto &state = s_states[slot];
    if (!Owned(bot, state, now))
    {
        state = {};
        state.owner = bot;
        state.player = bot->playerState;
        state.mapStatics = SVHS_GameStatics;
        state.nextScan = now + int32_t((slot * 37u) % 800u);
    }
    state.lastTime = now;
    state.origin = bot->entity->origin;
    if (now != s_scanTime)
    {
        s_scanTime = now;
        s_scans = 0;
    }
    // Scan at most four native lists per server frame. The per-bot stagger and
    // cooldown distribute physics queries without changing ordinary usermove.
    if (now < state.nextScan || s_scans >= 4)
        return;
    ++s_scans;
    state.nextScan = now + 1000 + int32_t((slot * 37u) % 200u);
    if (!SVHBL_LootTable())
        return;
    LootUsableList list;
    list.count = list.ignoredCount = 0;
    SVHBL_GetUseList(bot->entity, &list, Field<int32_t>(bot->playerState, 704));
    const bool needsWeapon = SV_HostBot_NeedsRangedWeapon(bot);
    int bestScore = 0;
    float bestDistance = 3.402823466e38f;
    const LootUsableItem *best = nullptr;
    Vec3 bestPosition{};
    uint32_t bestGeneration = 0;
    for (unsigned i = 0; i < list.count && i < 1000; ++i)
    {
        const auto &candidate = list.items[i];
        const auto &reference = candidate.reference;
        if (reference.useClass != 1 || candidate.ignored || !candidate.inDisplayDistance ||
            (candidate.flags & 4) || !SVHBL_InstanceInUse(reference.index))
            continue;
        const uint32_t generation = SVHBL_UseCount(reference.index);
        if (RecentlyAttempted(state, reference.index, generation, now))
            continue;
        const int score = Score(SVHBL_LootDefinition(reference.index), needsWeapon);
        if (!score)
            continue;
        Vec3 position{};
        SVHBL_UsePosition(&reference, &position);
        const float z = position.z - bot->entity->origin.z;
        const float distance = DistanceSquared(position, bot->entity->origin);
        // Same-floor, finite, nearby goals only. Native obstruction and use
        // range checks remain required, so items above/below walls are ignored.
        if (!(z >= -48.0f && z <= 96.0f) || !(distance <= 256.0f * 256.0f))
            continue;
        if (score > bestScore || (score == bestScore && distance < bestDistance))
        {
            best = &candidate;
            bestScore = score;
            bestDistance = distance;
            bestPosition = position;
            bestGeneration = generation;
        }
    }
    state.valid = best != nullptr;
    if (!best)
        return;
    state.goal = bestPosition;
    state.goalTime = now;
    state.index = best->reference.index;
    state.generation = bestGeneration;
    if (!(best->flags & 1))
        return; // Navigator/look must bring the bot within the real usable cone.
    const auto &reference = best->reference;
    state.attempts[state.nextAttempt++ % 8] = {reference.index, bestGeneration, now, true};
    // Same call used by the normal player activation callback, with a fresh
    // reuse generation. BR script eligibility performs all inventory mutation.
    SVHBL_UseScriptable(bot->entity, reference.index, reference.part, bestGeneration, false);
    state.valid = false;
}

extern "C" bool SV_HostBot_GetLootGoal(void *data, HostScale::Vec3 *goal)
{
    auto *bot = static_cast<BotLootView *>(data);
    GameStaticsScope gameStatics;
    if (!goal || !Enabled() || !Eligible(bot) || Slot(bot) >= 200 ||
        SV_HostBot_GasEvacuationRequired(data))
        return false;
    const auto &state = s_states[Slot(bot)];
    const int32_t now = SVHS_LevelTime;
    if (!state.valid || !Owned(bot, state, now) || now - state.goalTime > 3000 ||
        !SVHBL_InstanceInUse(state.index) || SVHBL_UseCount(state.index) != state.generation)
        return false;
    *goal = state.goal;
    return true;
}

extern "C" bool SV_HostBot_FaceLoot(void *data, HostScale::UserCmd *command)
{
    auto *bot = static_cast<BotLootView *>(data);
    GameStaticsScope gameStatics;
    if (!command || !Enabled() || !Eligible(bot) || bot->sentient->targetHandle ||
        (bot->scriptFlags & 12))
        return false;
    HostScale::Vec3 goal{};
    if (!SV_HostBot_GetLootGoal(bot, &goal) || (goal.x == 0 && goal.y == 0 && goal.z == 0))
        return false;
    // Like the native seek controller, replace an ordinary CODE_SEEK request
    // at the same tier. Stronger combat/script requests remain authoritative.
    if (bot->look.type > 3 && bot->look.endTime >= SVHS_LevelTime)
        return false;

    struct RestoreLook
    {
        BotLootView *bot;
        HostScale::BotLootLookRequest previous;

        ~RestoreLook()
        {
            bot->look = previous;
        }
    } restore{bot, bot->look};

    SVHBL_LookAtPoint(bot, &goal, 250, 3);
    // This native routine performs prediction, aim turn-speed limiting and the
    // complete usercmd angle encoding. No authored angle integers are written.
    SVHBL_UpdateDirection(bot, command);
    return true;
}
