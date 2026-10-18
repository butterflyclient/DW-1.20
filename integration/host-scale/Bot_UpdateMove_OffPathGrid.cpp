#include "sv_host_navigation.h"
#include "sv_host_bot_loot.h"
#include "sv_host_bot_equipment.h"
#include "SV_HostBotEquipmentBindings.h"
#include "DW_BotStyleProfile.h"
#include "sv_host_bot_slide.h"
#include "SV_HostBotGpuPlanner.h"
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
        int32_t nextPlan, lastTime, progressTime, gpuRetryAfter;
        unsigned sequence, failures;
        uint16_t target;
        bool valid;
        Vec3 pendingGoal;
        bool pendingGas;
        uint32_t pendingScriptType, pendingGasGeneration;
        Vec3 pendingScriptPosition, pendingGasCenter;
    };

    MeshGoal s_goals[200]{};

    struct UrgencyState
    {
        void *owner, *player, *statics;
        uint64_t ownedButtons;
        uint64_t profile;
        int32_t lastTime;
        SlideCancel::State slide;
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
        uint8_t opaque1808[10264];
        uint8_t skydivingState, opaque12073[3];
    };

#pragma pack(pop)
    static_assert(offsetof(SprintPlayerView, movementType) == 12);
    static_assert(offsetof(SprintPlayerView, movementFlags) == 20);
    static_assert(offsetof(SprintPlayerView, otherFlags) == 28);
    static_assert(offsetof(SprintPlayerView, groundEntity) == 626);
    static_assert(offsetof(SprintPlayerView, sprintButtonUpRequired) == 796);
    static_assert(offsetof(SprintPlayerView, weaponFlags) == 1796);
    static_assert(offsetof(SprintPlayerView, adsFraction) == 1804);
    static_assert(offsetof(SprintPlayerView, skydivingState) == 12072);
    static_assert(sizeof(SprintPlayerView) == 12076);
    constexpr uint64_t SprintRequest = 2;
    constexpr uint64_t TacticalSprintRequest = 0x800000000000ull;
    constexpr uint64_t TravelInterruptButtons = 0x4233ddull;
    constexpr float UrgentTravelDistance = 256.0f;
    int32_t s_planTime = -1;
    unsigned s_plans, s_nextPlanSlot, s_cpuPlans, s_gpuCommits;

    float DistanceSquared(const Vec3 &a, const Vec3 &b)
    {
        const float x = a.x - b.x, y = a.y - b.y, z = a.z - b.z;
        return x * x + y * y + z * z;
    }

    bool CurrentMappedBot(const BotNavigationView *bot, uint64_t *profileSeed = nullptr)
    {
        if (!bot || !bot->entity || !bot->playerState || !bot->sentient)
            return false;
        const unsigned slot = uint16_t(bot->entity->number);
        if (slot >= 200 || slot >= SVHS_ClientCount)
            return false;
        void *client = SVHS_Clients[slot];
        uint64_t profile = 0;
        const bool current = client &&
               static_cast<const uint8_t *>(client) + 1368 ==
                   reinterpret_cast<const uint8_t *>(bot) &&
               Field<int32_t>(client, 214756) == 2 && Field<Entity *>(client, 280) == bot->entity &&
               bot->entity->client == bot->playerState && bot->entity->sentient == bot->sentient &&
               SVHS_IsBotEntity(bot->entity) && SVHS_IsBotPlaying(client) &&
               DW_BotPolicy_ProfileSeed(slot, &profile);
        if (current && profileSeed)
            *profileSeed = profile;
        return current;
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
        if (SV_HostBot_GetGasGoal(const_cast<BotNavigationView *>(bot), &goal))
        {
            state.target = 0;
            // Long evacuations use reachable intermediate goals. The actual
            // native route still negotiates walls, floors and traversal.
            const float x = goal.x - bot->entity->origin.x;
            const float y = goal.y - bot->entity->origin.y;
            const float length = __builtin_sqrtf(x*x + y*y);
            if (length > 2048.0f)
            {
                goal.x = bot->entity->origin.x + x * (2048.0f / length);
                goal.y = bot->entity->origin.y + y * (2048.0f / length);
            }
            return true;
        }
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
        const bool evacuating = SV_HostBot_GasEvacuationRequired(bot);
        if (slot >= 200 || !bot->sentient || (!(bot->scriptFlags & 0x1000000) && !evacuating) ||
            !MeshAreaReady(nav) || !bot->playerState || entity->health <= 0 || bot->traversal ||
            SV_HostBot_InGulag(bot) || Field<uint16_t>(bot->playerState, 626) == 2047 ||
            Locked(bot))
        {
            if (slot < 200)
            {
                s_goals[slot].valid = false;
                HostBotPlanner::Cancel(slot);
            }
            return false;
        }

        auto &state = s_goals[slot];
        const int32_t now = SVHS_LevelTime;
        if (state.owner != bot || state.navigator != nav || state.player != bot->playerState ||
            now < state.lastTime)
        {
            HostBotPlanner::Cancel(slot);
            state = {};
            state.owner = bot; state.navigator = nav; state.player = bot->playerState;
            state.lastOrigin = entity->origin; state.lastTime = state.progressTime = now;
        }
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
            s_cpuPlans = s_gpuCommits = 0;
        }
        bool path = SVHS_NavHasPath(nav);
        if (HostBotPlanner::Pending(slot) && state.pendingGas != evacuating)
            HostBotPlanner::Cancel(slot);
        if (HostBotPlanner::Pending(slot))
        {
            BotGasState gas{};
            const bool newScriptGoal = !evacuating && bot->scriptGoalType >= 2 &&
                (bot->scriptGoalType != state.pendingScriptType ||
                 DistanceSquared(bot->scriptGoalPosition, state.pendingScriptPosition) > 1.0f);
            const bool newGasGoal = evacuating && SV_HostBot_GetGasState(&gas) &&
                (gas.generation != state.pendingGasGeneration ||
                 DistanceSquared(gas.closing ? gas.nextCenter : gas.currentCenter, state.pendingGasCenter) > 64.0f * 64.0f);
            Vec3 loot{};
            const bool newLoot = !evacuating && bot->scriptGoalType <= 1 &&
                SV_HostBot_GetLootGoal(bot, &loot) && DistanceSquared(loot, state.pendingGoal) > 96.0f * 96.0f;
            if (newScriptGoal || newGasGoal || newLoot) HostBotPlanner::Cancel(slot);
        }
        uint64_t profile = 0;
        Vec3 gpuWaypoint{};
        const bool mapped = CurrentMappedBot(bot, &profile);
        const auto gpu = mapped ? HostBotPlanner::Take(slot, bot, bot->playerState, nav,
            profile, nav->currentArea, entity->origin, gpuWaypoint) : HostBotPlanner::RouteState::Fallback;
        const bool gpuReady = gpu == HostBotPlanner::RouteState::Ready;
        const bool gpuPending = gpu == HostBotPlanner::RouteState::Pending;
        // A tactical reference is a nearby point, not proof of a usable route.
        // Preserve an existing native route; repair the no-route case even when
        // a streamed tactical graph supplies a point for this bot.
        if (state.valid && path && DistanceSquared(bot->nativeGoal, state.goal) > 1.0f)
            state.valid = false; // A native combat/script route replaced our request.
        const bool owned = state.valid && state.owner == bot && state.navigator == nav;
        if (path && bot->scriptGoalType >= 2 && !evacuating)
        {
            state.valid = false;
            return false;
        }
        Vec3 lootGoal{};
        const bool localLoot = bot->scriptGoalType <= 1 && SV_HostBot_GetLootGoal(bot, &lootGoal);
        if (path && !owned && !evacuating && !gpuReady && !gpuPending &&
            (!localLoot || DistanceSquared(bot->nativeGoal, lootGoal) < 32.0f * 32.0f))
            return false;
        const bool newLootGoal =
            localLoot && (!state.valid || DistanceSquared(state.goal, lootGoal) >= 32.0f * 32.0f);
        const bool reached =
            state.valid && DistanceSquared(entity->origin, state.goal) < 96.0f * 96.0f;
        const bool stuck = now - state.progressTime >= 750;
        if (evacuating && !state.pendingGas)
            state.nextPlan = now;
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
        if (gpuReady || (allowPlan && !gpuPending && now >= state.nextPlan &&
            (!path || reached || stuck || !state.valid || targetGone || newLootGoal) &&
            s_plans < (HostBotPlanner::Enabled() ? 16u : 2u) && slot >= s_nextPlanSlot))
        {
            Vec3 goal = gpuReady ? gpuWaypoint : Vec3{};
            ++s_plans;
            s_nextPlanSlot = slot + 1;
            state.nextPlan = now + 500 + int32_t((slot * 97) % 250);
            if (stuck || state.failures || (reached && !state.target))
            {
                ++state.sequence;
                if (stuck)
                    ++state.failures;
            }
            if (gpuReady || ChooseGoal(bot, state, goal))
            {
                // Targets can be on another floor, and a radial offset can land
                // outside the mesh. Resolve a reachable surface first instead
                // of repeatedly asking the pathfinder to route to raw XYZ.
                NavAreaHandle area{};
                bool projected = false;
                bool projectionAttempted = false;
                if (SV_HostNav_BeginRouteProjection())
                {
                    projectionAttempted = true;
                    SVHS_NavClosestArea(&area, &goal, &nav->currentArea, nav->pathConfiguration);
                    if (area.reference && *area.reference && area.space)
                    {
                        Vec3 snapped{};
                        SVHS_NavProjectArea(&area, &snapped, &goal, nullptr);
                        if (__builtin_isfinite(snapped.x) && __builtin_isfinite(snapped.y) &&
                            __builtin_isfinite(snapped.z) &&
                            DistanceSquared(entity->origin, snapped) > 32.0f * 32.0f)
                        {
                            goal = snapped;
                            projected = true;
                            BotGasState gas{};
                            if (evacuating && !gpuReady && SV_HostBot_GetGasState(&gas))
                            {
                                const Vec3 center = gas.closing ? gas.nextCenter : gas.currentCenter;
                                const float radius = gas.closing ? gas.nextRadius : gas.currentRadius;
                                const float x = goal.x - center.x, y = goal.y - center.y;
                                const float ox = entity->origin.x - center.x, oy = entity->origin.y - center.y;
                                // A distant bot needs intermediate waypoints
                                // outside the circle. Reject a snapped goal
                                // farther into gas; native paths may still
                                // detour around walls on their way inward.
                                const float distance = __builtin_sqrtf(x*x + y*y);
                                const float current = __builtin_sqrtf(ox*ox + oy*oy);
                                projected = distance < radius - 32.0f || distance < current - 16.0f;
                            }
                            // A copied GPU graph route may first go sideways
                            // or outward around a wall before reaching its gas
                            // destination. Do not discard that necessary first
                            // hop on radial distance alone. PathToGoal below
                            // must still validate/install the native segment;
                            // stale objective/circle results were rejected above.
                        }
                    }
                    SV_HostNav_End(0);
                }
                bool queued = false;
                if (projected && !gpuReady && mapped && HostBotPlanner::Enabled() && now >= state.gpuRetryAfter)
                {
                    NavSearchSpec specification{};
                    __builtin_memcpy(&specification, nav->pathConfiguration, sizeof(specification));
                    queued = HostBotPlanner::Queue(slot, bot, bot->playerState, nav, profile,
                        nav->currentArea, area, specification, entity->origin, goal);
                    if (queued)
                    {
                        state.pendingGoal = goal;
                        state.pendingGas = evacuating;
                        state.pendingScriptType = bot->scriptGoalType;
                        state.pendingScriptPosition = bot->scriptGoalPosition;
                        BotGasState gas{};
                        if (evacuating && SV_HostBot_GetGasState(&gas))
                        {
                            state.pendingGasGeneration = gas.generation;
                            state.pendingGasCenter = gas.closing ? gas.nextCenter : gas.currentCenter;
                        }
                        state.nextPlan = now + 16;
                    }
                }
                SVHS_NavDestroyArea(&area);
                // PathToGoal owns goal bookkeeping and native area/path handles.
                // Suspend approximate closest search while making an actual route.
                bool planned = false;
                bool attempted = false;
                if (projected && !queued && (gpuReady ? s_gpuCommits < 8 : s_cpuPlans < 2))
                {
                    attempted = true;
                    if (gpuReady) ++s_gpuCommits; else ++s_cpuPlans;
                    const bool suspended = SV_HostNav_SuspendClosest(true);
                    path = SVHS_BotPathToGoal(bot, &goal, 32.0f, "mesh fallback") != 0;
                    SV_HostNav_SuspendClosest(suspended);
                    planned = path;
                    HostBotPlanner::RecordCommit(gpuReady, planned, evacuating);
                    if (planned)
                    {
                        state.goal = goal;
                        state.valid = true;
                        state.pendingGas = evacuating;
                        state.progressTime = now;
                    }
                    else
                        state.valid = false;
                }
                if (gpuReady && ((projectionAttempted && !projected) || (attempted && !planned)))
                {
                    // A copied graph is a planning hint. Dynamic obstacles or
                    // stricter native search rules can reject its first hop.
                    // Give the stable destination a bounded native fallback
                    // before submitting the same graph request again.
                    state.gpuRetryAfter = now + 1000;
                }
                if (planned)
                    state.failures = 0;
                else if (!queued && (attempted || !projected))
                {
                    ++state.failures;
                    // Keep retries responsive and fair, especially while gas
                    // is closing. Do not impose seconds of motionless backoff.
                    state.nextPlan = now + (evacuating ? 100 : 250) + int32_t(slot % 8) * 16;
                }
            }
        }
        // Pending GPU work or failed projection must not erase native motion
        // or an existing route. Only take movement ownership with a real path.
        path = SVHS_NavHasPath(nav);
        if (path && (!state.valid || DistanceSquared(entity->origin, state.goal) > 32.0f * 32.0f))
        {
            Field<uint16_t>(command, 156) = 0;
            if (allowPlan && !evacuating)
                SVHS_BotMovePathing(bot, command);
            else
                // The native steering/avoidance leaf updates direction without
                // repeating the all-player friendly-speed scan or route search.
                SVHS_BotSteerPath(bot, command, 127);
            return true;
        }
        return false;
    }
} // namespace

extern "C" void SV_HostBot_UpdateTravelUrgency(void *data,
                                               HostScale::UserCmd *command,
                                               bool reusedCommand)
{
    using namespace HostScale;
    auto *bot = static_cast<BotNavigationView *>(data);
    const unsigned slot = bot && bot->entity ? uint16_t(bot->entity->number) : 200;
    uint64_t profile = 0;
    if (!command || slot >= 200 || !Enabled() || !CurrentMappedBot(bot, &profile))
        return;
    auto &state = s_urgency[slot];
    const bool same =
        state.owner == bot && state.player == bot->playerState && state.statics == SVHS_GameStatics &&
        state.profile == profile && SVHS_LevelTime >= state.lastTime;
    if (same)
    {
        // Native Bot_Think carries the preceding crouch button even on a full
        // thought. Release only our carried stance bits; explicit script input
        // keeps ownership and interrupts this optional sequence below.
        const uint64_t stance = state.ownedButtons &
            (SlideCancel::SlideRequest | SlideCancel::CrouchRequest) &
            ~uint64_t(Field<uint32_t>(bot, 8988));
        command->buttons &= ~(stance | (reusedCommand ? state.ownedButtons &
            (SprintRequest | TacticalSprintRequest) : 0));
    }
    else
    {
        state = {};
        state.owner = bot;
        state.player = bot->playerState;
        state.statics = SVHS_GameStatics;
        state.profile = profile;
        SlideCancel::Reset(state.slide, profile, SVHS_LevelTime);
    }
    state.ownedButtons = 0;
    state.lastTime = SVHS_LevelTime;
    const auto *player = reinterpret_cast<const SprintPlayerView *>(bot->playerState);
    if (!player || !bot->sentient || bot->entity->health <= 0 || bot->traversal ||
        SV_HostBot_InGulag(bot) || Locked(bot) || uint32_t(player->movementType) > 1 ||
        (player->otherFlags & 0x800) || player->groundEntity == 2047 ||
        (player->movementFlags & (1ull << 5)) || player->skydivingState ||
        SV_HostBot_EquipmentActionActive(bot) || (player->weaponFlags & (1ull << 42)) ||
        !__builtin_isfinite(player->adsFraction) || player->adsFraction > 0.0f ||
        (command->buttons & TravelInterruptButtons) || Field<int8_t>(command, 156) < 64 ||
        !MeshAreaReady(bot->navigator) || !SVHS_NavHasPath(bot->navigator) ||
        SVHS_BotCanFire(bot) ||
        DistanceSquared(bot->entity->origin, bot->nativeGoal) <
            UrgentTravelDistance * UrgentTravelDistance)
    {
        SlideCancel::Update(state.slide, SVHS_LevelTime, player ? player->movementFlags : 0,
                            false, false);
        return;
    }

    Vec3 lootGoal{};
    const bool looting = SV_HostBot_GetLootGoal(bot, &lootGoal);
    const bool canStart = !looting && !player->sprintButtonUpRequired &&
                          !(player->movementFlags & (SlideCancel::Crouched | 1));
    const auto slide = SlideCancel::Update(state.slide, SVHS_LevelTime, player->movementFlags,
                                           !looting, canStart);
    if (slide.active)
    {
        state.ownedButtons = slide.buttons & ~command->buttons;
        command->buttons |= slide.buttons;
        return;
    }
    if (player->sprintButtonUpRequired)
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
        state.ownedButtons =
            (command->buttons & ~original) & (SprintRequest | TacticalSprintRequest);
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
    if ((!canFire || SV_HostBot_GasEvacuationRequired(bot)) && Enabled() && FollowMesh(bot, command, true))
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
    if (SVHS_BotCanFire(bot) && !SV_HostBot_GasEvacuationRequired(bot))
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
    if (owned || nativePath || HostBotPlanner::Pending(slot) || SV_HostBot_GasEvacuationRequired(bot))
    {
        // BotThink normally installs this native TLS context around steering.
        // Cached decisions bypass BotThink, so preserve that exact contract here.
        auto *slots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
        auto &statics = *reinterpret_cast<void **>(slots[SVHS_BotTlsIndex] + 16);
        void *previous = statics;
        statics = SVHS_GameStatics;
        if (owned || HostBotPlanner::Pending(slot) || SV_HostBot_GasEvacuationRequired(bot))
            FollowMesh(bot, command, SV_HostBot_GasEvacuationRequired(bot));
        else
            SVHS_BotSteerPath(bot, command, 127);
        statics = previous;
    }
}

// Script bridge: values only. The native VM invokes this on the server thread.
// 0 preserves stock fallback, 1 coalesces pending work, 2 supplies a validated far goal.
extern "C" unsigned SV_HostBot_RequestRoamGoal(void *data, const HostScale::Vec3 *circle,
                                               float radius, HostScale::Vec3 *out,
                                               void *scriptContext)
{
    using namespace HostScale;
    auto *bot = static_cast<BotNavigationView *>(data);
    uint64_t profile = 0;
    if (!circle || !out || !bot || !CurrentMappedBot(bot, &profile))
        return 0;
    const unsigned slot = uint16_t(bot->entity->number);
    auto *nav = bot->navigator;
    if (!HostBotPlanner::Enabled())
    {
        HostBotPlanner::CancelRoam(slot);
        return 0;
    }
    if (!MeshAreaReady(nav) || bot->entity->health <= 0 || bot->traversal || Locked(bot) ||
        bot->scriptGoalType >= uint32_t(HostBotPlanner::ScriptGoalPriority::Guard) ||
        SV_HostBot_InGulag(bot) || SV_HostBot_GasEvacuationRequired(bot) ||
        Field<uint16_t>(bot->playerState, 626) == 2047 ||
        Field<uint8_t>(bot->playerState, 12072) != 0 || !__builtin_isfinite(circle->x) ||
        !__builtin_isfinite(circle->y) || !__builtin_isfinite(circle->z) ||
        !__builtin_isfinite(radius) || radius <= 32.0f)
    {
        HostBotPlanner::CancelRoam(slot);
        return 0;
    }
    NavSearchSpec spec{};
    __builtin_memcpy(&spec, nav->pathConfiguration, sizeof(spec));
    BotGasState gas{};
    const uint32_t gasGeneration = SV_HostBot_GetGasState(&gas) ? gas.generation : 0;
    Vec3 destination{};
    const auto result = HostBotPlanner::RequestRoam(
        slot, bot, bot->playerState, nav, profile, nav->currentArea, spec, bot->entity->origin,
        *circle, radius - 32.0f, gasGeneration, bot->scriptGoalType, bot->scriptGoalPosition,
        SVHS_NavHasPath(nav), destination);
    if (result != HostBotPlanner::RouteState::Ready)
    {
        if (result == HostBotPlanner::RouteState::Fallback)
            HostBotPlanner::BindNativeRoamFallback(slot, bot, bot->playerState, nav, scriptContext);
        return result == HostBotPlanner::RouteState::Pending ? 1u : 0u;
    }
    if (!HostBotPlanner::AdmitRoamValidation(slot))
        return 1;
    const uint64_t begin = Clock();
    const bool acquiredBotScope = SV_HostNav_BeginBot();
    const bool previous = SV_HostNav_SuspendClosest(true);
    NavAreaHandle area{};
    SVHS_NavClosestArea(&area, &destination, &nav->currentArea, nav->pathConfiguration);
    bool accepted = area.reference && *area.reference && area.space;
    Vec3 snapped{};
    if (accepted)
    {
        SVHS_NavProjectArea(&area, &snapped, &destination, nullptr);
        accepted =
            HostBotPlanner::RoamCandidateAllowed(bot->entity->origin, snapped, *circle,
                                                 radius - 32.0f, !HostBotPlanner::RoamRepair(slot));
    }
    SVHS_NavDestroyArea(&area);
    if (accepted)
    {
        // Match BotThink's verified BgStatic contract even when invoked from
        // a script thread outside its native brain scope. Preserve the caller.
        auto *slots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
        auto &statics = *reinterpret_cast<void **>(slots[SVHS_BotTlsIndex] + 16);
        void *previousStatics = statics;
        statics = SVHS_GameStatics;
        accepted = SVHS_BotPathToGoal(bot, &snapped, 1024.0f, "BR GPU roam") != 0;
        statics = previousStatics;
    }
    SV_HostNav_SuspendClosest(previous);
    if (acquiredBotScope)
        SV_HostNav_EndBot();
    HostBotPlanner::RecordRoamValidation(Clock() - begin);
    HostBotPlanner::FinishRoam(slot, accepted, accepted ? &snapped : nullptr);
    if (!accepted)
        return 1;
    *out = snapped;
    return 2;
}

extern "C" void SV_HostBot_CancelRoamGoal(void *data)
{
    auto *bot = static_cast<BotNavigationView *>(data);
    if (bot && bot->entity)
        HostBotPlanner::CancelRoam(uint16_t(bot->entity->number));
}
