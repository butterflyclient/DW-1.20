#include "sv_host_navigation.h"
#include "sv_host_bot_loot.h"
#include "sv_host_bot_equipment.h"
#include "SV_HostBotEquipmentBindings.h"
#include <intrin.h>

namespace
{
    using namespace HostScale;

    // Replay bot_info_t prefix and movement state. Keep unknown fields opaque;
    // offsets come from the verified native off-grid and path-generation bodies.
    struct BotNavigationView
    {
        Entity *entity;
        Sentient *sentient;
        uint8_t opaque16[344];
        Nav2DQueryView *navigator;
        uint8_t opaque368[80];
        uint8_t *playerState;
        uint8_t opaque456[16];
        Vec3 scriptGoalPosition;
        uint8_t opaque484[32];
        uint32_t scriptGoalType;
        uint8_t opaque520[16];
        Vec3 nativeGoal;
        uint8_t opaque548[72];
        int32_t traversal;
        uint8_t opaque624[16];
        int32_t noPathFoundTime;
        uint8_t opaque644[8340];
        uint32_t scriptFlags;
        uint8_t opaque8988[19148];
        Vec3 strafeDirection;
    };

    static_assert(offsetof(BotNavigationView, navigator) == 360);
    static_assert(offsetof(BotNavigationView, playerState) == 448);
    static_assert(offsetof(BotNavigationView, scriptGoalPosition) == 472);
    static_assert(offsetof(BotNavigationView, scriptGoalType) == 516);
    static_assert(offsetof(BotNavigationView, nativeGoal) == 536);
    static_assert(offsetof(BotNavigationView, traversal) == 620);
    static_assert(offsetof(BotNavigationView, noPathFoundTime) == 640);
    static_assert(offsetof(BotNavigationView, scriptFlags) == 8984);
    static_assert(offsetof(BotNavigationView, strafeDirection) == 28136);

    struct MeshGoal
    {
        void *owner, *navigator, *player;
        Vec3 goal, lastOrigin;
        int32_t nextPlan, lastTime, progressTime;
        unsigned sequence, failures;
        uint16_t target;
        bool valid;
    };

    MeshGoal s_goals[200]{};
    struct UrgencyState
    {
        void *owner, *player;
        uint64_t ownedButtons;
        int32_t lastTime;
    };
    UrgencyState s_urgency[200]{};

#pragma pack(push, 4)
    struct SprintPlayerView
    {
        int32_t commandTime, frozenTime;
        uint32_t opaque8;
        int32_t movementType, movementTime;
        uint64_t movementFlags, otherFlags;
        uint8_t opaque36[590];
        uint16_t groundEntity;
        uint8_t opaque628[168];
        int32_t sprintButtonUpRequired;
        uint8_t opaque800[996];
        uint64_t weaponFlags;
        float adsFraction;
    };
#pragma pack(pop)
    static_assert(offsetof(SprintPlayerView, movementType) == 12);
    static_assert(offsetof(SprintPlayerView, movementFlags) == 20);
    static_assert(offsetof(SprintPlayerView, otherFlags) == 28);
    static_assert(offsetof(SprintPlayerView, groundEntity) == 626);
    static_assert(offsetof(SprintPlayerView, sprintButtonUpRequired) == 796);
    static_assert(offsetof(SprintPlayerView, weaponFlags) == 1796);
    static_assert(offsetof(SprintPlayerView, adsFraction) == 1804);
    static_assert(sizeof(SprintPlayerView) == 1808);
    constexpr uint64_t SprintRequest = 2;
    constexpr uint64_t TacticalSprintRequest = 0x800000000000ull;
    constexpr uint64_t TravelInterruptButtons = 0x4233ddull;
    int32_t s_planTime = -1;
    unsigned s_plans, s_nextPlanSlot;

    float DistanceSquared(const Vec3 &a, const Vec3 &b)
    {
        const float x = a.x - b.x, y = a.y - b.y, z = a.z - b.z;
        return x * x + y * y + z * z;
    }

    bool Locked(const BotNavigationView *bot)
    {
        auto *player = bot->playerState;
        return Field<int32_t>(player, 0) < Field<int32_t>(player, 4) || (bot->scriptFlags & 4) ||
               (Field<uint8_t>(player, 24) & 1) || (Field<uint32_t>(player, 364) & 0xe0);
    }

    bool MeshAreaReady(const Nav2DQueryView *nav)
    {
        return nav && nav->vtable &&
               nav->vtable[45] == reinterpret_cast<uintptr_t>(&SVHS_Nav2DClosest) &&
               nav->currentArea.reference && *nav->currentArea.reference && nav->currentArea.space;
    }

    bool ChooseGoal(const BotNavigationView *bot, MeshGoal &state, Vec3 &goal)
    {
        if (bot->scriptGoalType >= 2 && bot->scriptGoalType <= 6)
        {
            // Replan the exact native guard/objective/critical destination when
            // its route is missing. An exterior patrol must never replace it.
            state.target = 0;
            goal = bot->scriptGoalPosition;
            return __builtin_isfinite(goal.x) && __builtin_isfinite(goal.y) &&
                   __builtin_isfinite(goal.z);
        }
        // Combat belongs to the native awareness/target controller. A fallback
        // route must not hunt an unseen enemy across the entire map or circle
        // a nearby teammate. Prefer a useful, native usable loot destination.
        // Native type0/1 is none/hunt. Guard, camp, objective, critical gas
        // escapes and tactical goals retain their script priority and route.
        if (bot->scriptGoalType <= 1 &&
            SV_HostBot_GetLootGoal(const_cast<BotNavigationView *>(bot), &goal))
        {
            state.target = 0;
            return true;
        }
        Entity *selected = nullptr;
        float best = 3.402823466e38f;
        TeamFlags enemies{};
        SVHS_EnemyTeamFlags(&enemies, bot->sentient->team);
        for (unsigned slot = 0; slot < SVHS_ClientCount && slot < 200; ++slot)
        {
            void *client = SVHS_Clients[slot];
            if (!client || Field<uint8_t>(client, 8) < 5)
                continue;
            auto *entity = Field<Entity *>(client, 280);
            if (!entity || entity == bot->entity || !entity->sentient || entity->health <= 0)
                continue;
            const unsigned team = entity->sentient->team;
            const bool hostile =
                team < 160 && (enemies.words[team >> 5] & (0x80000000u >> (team & 31)));
            const float distance = DistanceSquared(entity->origin, bot->entity->origin);
            if (hostile && bot->sentient->targetHandle == uint16_t(entity->number + 1))
            {
                selected = entity;
                break;
            }
            if (!hostile && team == bot->sentient->team && team > 0 && team < 153 &&
                distance > 640.0f * 640.0f && distance < best)
            {
                selected = entity;
                best = distance;
            }
        }
        if (state.failures)
            selected = nullptr; // Get clear of the obstacle before resuming the target route.
        state.target = selected ? uint16_t(selected->number + 1) : 0;
        // Disperse patrol destinations and failed-route retries. These are
        // requests, not straight-line movement: only a successful native path
        // is followed. No-path leaves the bot stopped until its next retry.
        constexpr Vec3 directions[8] = {{1, 0, 0},
                                        {0.7071f, 0.7071f, 0},
                                        {0, 1, 0},
                                        {-0.7071f, 0.7071f, 0},
                                        {-1, 0, 0},
                                        {-0.7071f, -0.7071f, 0},
                                        {0, -1, 0},
                                        {0.7071f, -0.7071f, 0}};
        const auto &direction = directions[(unsigned(bot->entity->number) + state.sequence) & 7];
        goal = selected ? selected->origin : bot->entity->origin;
        float x = goal.x - bot->entity->origin.x;
        float y = goal.y - bot->entity->origin.y;
        const float extent =
            __builtin_fabsf(x) > __builtin_fabsf(y) ? __builtin_fabsf(x) : __builtin_fabsf(y);
        if (extent > 2048.0f)
        {
            const float fraction = 2048.0f / extent;
            goal = {bot->entity->origin.x + x * fraction,
                    bot->entity->origin.y + y * fraction,
                    bot->entity->origin.z + (goal.z - bot->entity->origin.z) * fraction};
        }
        // Keep room between squad members. A stuck bot tries a shorter lateral
        // escape route rather than repeatedly requesting the same obstruction.
        const bool enemy = selected && bot->sentient->targetHandle == state.target;
        const float spread = selected ? (enemy ? 64.0f : 256.0f) : state.failures ? 256.0f : 768.0f;
        goal.x += direction.x * spread;
        goal.y += direction.y * spread;
        return __builtin_isfinite(goal.x) && __builtin_isfinite(goal.y) &&
               __builtin_isfinite(goal.z);
    }

    bool FollowMesh(BotNavigationView *bot, UserCmd *command, bool allowPlan)
    {
        auto *nav = bot->navigator;
        auto *entity = bot->entity;
        const unsigned slot = entity ? uint16_t(entity->number) : 200;
        if (slot >= 200 || !bot->sentient || !(bot->scriptFlags & 0x1000000) ||
            !MeshAreaReady(nav) || !bot->playerState || entity->health <= 0 || bot->traversal ||
            SV_HostBot_InGulag(bot) || Field<uint16_t>(bot->playerState, 626) == 2047 ||
            Locked(bot))
        {
            if (slot < 200)
                s_goals[slot].valid = false;
            return false;
        }

        auto &state = s_goals[slot];
        const int32_t now = SVHS_LevelTime;
        if (state.owner != bot || state.navigator != nav || state.player != bot->playerState ||
            now < state.lastTime)
            state = {bot, nav, bot->playerState, {}, entity->origin, 0, now, now, 0, 0, 0, false};
        state.lastTime = now;
        if (DistanceSquared(entity->origin, state.lastOrigin) > 24.0f * 24.0f)
        {
            state.lastOrigin = entity->origin;
            state.progressTime = now;
        }
        if (s_planTime != now)
        {
            if (!s_plans || now < s_planTime)
                s_nextPlanSlot = 0;
            s_planTime = now;
            s_plans = 0;
        }
        bool path = SVHS_NavHasPath(nav);
        // A tactical reference is a nearby point, not proof of a usable route.
        // Preserve an existing native route; repair the no-route case even when
        // a streamed tactical graph supplies a point for this bot.
        if (state.valid && path && DistanceSquared(bot->nativeGoal, state.goal) > 1.0f)
            state.valid = false; // A native combat/script route replaced our request.
        const bool owned = state.valid && state.owner == bot && state.navigator == nav;
        if (path && bot->scriptGoalType >= 2)
        {
            state.valid = false;
            return false;
        }
        Vec3 lootGoal{};
        const bool localLoot = bot->scriptGoalType <= 1 && SV_HostBot_GetLootGoal(bot, &lootGoal);
        if (path && !owned && (!localLoot ||
            DistanceSquared(bot->nativeGoal, lootGoal) < 32.0f * 32.0f))
            return false;
        const bool newLootGoal = localLoot &&
            (!state.valid || DistanceSquared(state.goal, lootGoal) >= 32.0f * 32.0f);
        const bool reached =
            state.valid && DistanceSquared(entity->origin, state.goal) < 96.0f * 96.0f;
        const bool stuck = now - state.progressTime >= 750;
        if (reached || stuck || newLootGoal)
            state.nextPlan = now;
        bool targetGone = false;
        if (state.target && state.target <= SVHS_ClientCount && state.target <= 200)
        {
            void *client = SVHS_Clients[state.target - 1];
            const Entity *target = client ? Field<Entity *>(client, 280) : nullptr;
            targetGone = !target || target->health <= 0;
            if (targetGone)
                state.nextPlan = now;
        }
        if (allowPlan && now >= state.nextPlan &&
            (!path || reached || stuck || !state.valid || targetGone || newLootGoal) && s_plans < 2 &&
            slot >= s_nextPlanSlot)
        {
            Vec3 goal{};
            ++s_plans;
            s_nextPlanSlot = slot + 1;
            state.nextPlan = now + 500 + int32_t((slot * 97) % 250);
            state.progressTime = now;
            if (stuck || state.failures || (reached && !state.target))
            {
                ++state.sequence;
                if (stuck)
                    ++state.failures;
            }
            if (ChooseGoal(bot, state, goal))
            {
                // Targets can be on another floor, and a radial offset can land
                // outside the mesh. Resolve a reachable surface first instead
                // of repeatedly asking the pathfinder to route to raw XYZ.
                NavAreaHandle area{};
                bool projected = false;
                if (SV_HostNav_BeginRouteProjection())
                {
                    SVHS_NavClosestArea(&area, &goal, &nav->currentArea, nav->pathConfiguration);
                    if (area.reference && *area.reference && area.space)
                    {
                        Vec3 snapped{};
                        SVHS_NavProjectArea(&area, &snapped, &goal, nullptr);
                        if (__builtin_isfinite(snapped.x) && __builtin_isfinite(snapped.y) &&
                            __builtin_isfinite(snapped.z) &&
                            DistanceSquared(entity->origin, snapped) > 96.0f * 96.0f)
                        {
                            goal = snapped;
                            projected = true;
                        }
                    }
                    SVHS_NavDestroyArea(&area);
                    SV_HostNav_End(0);
                }
                // PathToGoal owns goal bookkeeping and native area/path handles.
                // Suspend approximate closest search while making an actual route.
                bool planned = false;
                if (projected)
                {
                    const bool suspended = SV_HostNav_SuspendClosest(true);
                    path = SVHS_BotPathToGoal(bot, &goal, 32.0f, "mesh fallback") != 0;
                    SV_HostNav_SuspendClosest(suspended);
                    planned = path;
                    state.goal = goal;
                    state.valid = path;
                }
                else
                {
                    path = false;
                    state.valid = false;
                }
                if (planned)
                    state.failures = 0;
                else
                {
                    ++state.failures;
                    state.nextPlan += int32_t(state.failures < 4 ? state.failures : 4) * 500;
                }
            }
        }
        Field<uint16_t>(command, 156) = 0;
        if (path && !reached)
        {
            if (allowPlan)
                SVHS_BotMovePathing(bot, command);
            else
                // The native steering/avoidance leaf updates direction without
                // repeating the all-player friendly-speed scan or route search.
                SVHS_BotSteerPath(bot, command, 127);
        }
        return true;
    }
} // namespace

extern "C" void SV_HostBot_UpdateTravelUrgency(void *data, HostScale::UserCmd *command,
                                               bool reusedCommand)
{
    using namespace HostScale;
    auto *bot = static_cast<BotNavigationView *>(data);
    const unsigned slot = bot && bot->entity ? uint16_t(bot->entity->number) : 200;
    if (!command || slot >= 200)
        return;
    auto &state = s_urgency[slot];
    const bool same = state.owner == bot && state.player == bot->playerState &&
                      SVHS_LevelTime >= state.lastTime;
    if (same && reusedCommand)
        command->buttons &= ~state.ownedButtons;
    state = {bot, bot->playerState, 0, SVHS_LevelTime};
    const auto *player = reinterpret_cast<const SprintPlayerView *>(bot->playerState);
    if (!Enabled() || !player || !bot->sentient || bot->entity->health <= 0 ||
        bot->traversal || SV_HostBot_InGulag(bot) || Locked(bot) ||
        uint32_t(player->movementType) > 1 || (player->otherFlags & 0x800) ||
        player->groundEntity == 2047 || player->sprintButtonUpRequired ||
        (player->weaponFlags & (1ull << 42)) || !__builtin_isfinite(player->adsFraction) ||
        player->adsFraction > 0.0f ||
        (command->buttons & TravelInterruptButtons) || Field<int8_t>(command, 156) < 64 ||
        !MeshAreaReady(bot->navigator) || !SVHS_NavHasPath(bot->navigator) ||
        SVHS_BotCanFire(bot) ||
        DistanceSquared(bot->entity->origin, bot->nativeGoal) < 768.0f * 768.0f)
        return;

    // Reused commands bypass BotThink's TLS scope. These two original routines
    // read the native weapon map/statics; restore the caller's exact TLS value.
    auto *slots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
    auto &statics = *reinterpret_cast<void **>(slots[SVHS_BotTlsIndex] + 16);
    void *previous = statics;
    statics = SVHS_GameStatics;
    auto *map = SVHBE_WeaponMap();
    if (map && SVHS_SprintLeftRaw(map, player, command->serverTime) > 500)
    {
        const uint64_t original = command->buttons;
        UserCmd decision = *command;
        decision.buttons &= ~SprintRequest;
        SVHS_BotUpdateSprinting(bot, &decision);
        // Ordinary sprint is approved by the complete native bot policy. The
        // real PM_UpdateSprint subsequently runs CanStartSprint and its meter
        // test; this command request never modifies sprint timers or physics.
        if (decision.buttons & SprintRequest)
        {
            command->buttons |= SprintRequest;
            if (!(player->movementFlags & (1ull << 53)))
                command->buttons |= TacticalSprintRequest;
        }
        state.ownedButtons = (command->buttons & ~original) & (SprintRequest | TacticalSprintRequest);
    }
    statics = previous;
}

extern "C" unsigned Bot_UpdateMove_OffPathGrid(void *data, HostScale::UserCmd *command)
{
    using namespace HostScale;
    auto *bot = static_cast<BotNavigationView *>(data);
    const bool canFire = SVHS_BotCanFire(data);
    if (Enabled() && SV_HostBot_InGulag(bot))
    {
        const unsigned slot = bot->entity ? uint16_t(bot->entity->number) : 200;
        if (slot < 200)
            s_goals[slot].valid = false; // An exterior fallback cannot own an arena route.
        if (canFire || !bot->playerState || Locked(bot))
            return 0;
        // Without a current area and native path, blind strafe aims through
        // arena walls. Preserve weapon, buttons and view while entry resolves.
        if (!MeshAreaReady(bot->navigator) || !SVHS_NavHasPath(bot->navigator))
        {
            Field<uint16_t>(command, 156) = 0;
            return 1;
        }
        return 0; // Let the native arena path controller steer a ready route.
    }
    // Do not consume this movement stage before the native combat/melee
    // controller. This applies equally to bot and human opponents.
    if (!canFire && Enabled() && FollowMesh(bot, command, true))
        return 1;
    const bool failedLongEnough =
        bot->noPathFoundTime && SVHS_LevelTime - bot->noPathFoundTime > 750;
    const bool airborneWithoutPath =
        !SVHS_NavHasPath(bot->navigator) && Field<uint16_t>(bot->playerState, 626) == 2047;
    if (canFire || Locked(bot) || (!failedLongEnough && !airborneWithoutPath))
        return 0;
    Vec3 forward{}, right{};
    SVHS_BotYawVectors(Field<float>(bot->playerState, 464), &forward, &right);
    const auto &direction = bot->strafeDirection;
    Field<int8_t>(command, 156) = int8_t(int(
        ((forward.y * direction.y + forward.x * direction.x) + forward.z * direction.z) * 127.0f));
    Field<int8_t>(command, 157) = int8_t(
        int(((right.y * direction.y + right.x * direction.x) + right.z * direction.z) * 127.0f));
    return 1;
}

extern "C" void SV_HostNav_RefreshBotMovement(void *data, HostScale::UserCmd *command)
{
    using namespace HostScale;
    auto *bot = static_cast<BotNavigationView *>(data);
    auto *entity = bot->entity;
    const unsigned slot = entity ? uint16_t(entity->number) : 200;
    if (!Enabled() || slot >= 200)
        return;
    const bool gulag = SV_HostBot_InGulag(bot);
    if (gulag)
        s_goals[slot].valid = false;
    if (SVHS_BotCanFire(bot))
        return;
    const auto &state = s_goals[slot];
    auto *nav = bot->navigator;
    const bool owned = state.valid && state.owner == bot && state.player == bot->playerState &&
                       state.navigator == nav;
    const bool nativePath = !owned && nav && bot->sentient && bot->playerState &&
                            entity->health > 0 && !bot->traversal && !Locked(bot) &&
                            Field<uint16_t>(bot->playerState, 626) != 2047 &&
                            (!gulag || MeshAreaReady(nav)) && SVHS_NavHasPath(nav);
    // Refresh fallback-owned and native routes without choosing another goal.
    // Combat firing, airborne and locked/scripted movement retain their commands.
    if (owned || nativePath)
    {
        // BotThink normally installs this native TLS context around steering.
        // Cached decisions bypass BotThink, so preserve that exact contract here.
        auto *slots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
        auto &statics = *reinterpret_cast<void **>(slots[SVHS_BotTlsIndex] + 16);
        void *previous = statics;
        statics = SVHS_GameStatics;
        if (owned)
            FollowMesh(bot, command, false);
        else
            SVHS_BotSteerPath(bot, command, 127);
        statics = previous;
    }
}
