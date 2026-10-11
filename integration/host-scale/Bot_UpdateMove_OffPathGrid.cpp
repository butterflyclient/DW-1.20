#include "sv_host_navigation.h"
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
        uint8_t opaque456[164];
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
        return Field<int32_t>(player, 0) < Field<int32_t>(player, 4) ||
            (bot->scriptFlags & 4) || (Field<uint8_t>(player, 24) & 1) ||
            (Field<uint32_t>(player, 364) & 0xe0);
    }

    bool ChooseGoal(const BotNavigationView *bot, MeshGoal &state, Vec3 &goal)
    {
        // Tactical points are absent in this asset set. Pick a local destination
        // from real participants, then let the native navigator find a route.
        // Do not invent tactical points, visibility links or navigation edges.
        Entity *selected = nullptr;
        Entity *retained = nullptr;
        float retainedScore = 3.402823466e38f;
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
            const bool hostile = team < 160 && (enemies.words[team >> 5] & (0x80000000u >> (team & 31)));
            const float distance = DistanceSquared(entity->origin, bot->entity->origin);
            const float score = distance + (hostile ? 0.0f : 16777216.0f);
            if (state.target == uint16_t(entity->number + 1))
            {
                retained = entity;
                retainedScore = score;
            }
            if (score < best)
            {
                selected = entity;
                best = score;
            }
        }
        // Keep a live destination unless an alternative is substantially closer.
        // Small movements by two adjacent opponents must not reverse the route.
        if (retained && retainedScore <= best * 1.5625f)
            selected = retained;
        state.target = selected ? uint16_t(selected->number + 1) : 0;
        // Disperse patrol destinations and failed-route retries. These are
        // requests, not straight-line movement: only a successful native path
        // is followed. No-path leaves the bot stopped until its next retry.
        constexpr Vec3 directions[8] = {
            {1, 0, 0}, {0.7071f, 0.7071f, 0}, {0, 1, 0}, {-0.7071f, 0.7071f, 0},
            {-1, 0, 0}, {-0.7071f, -0.7071f, 0}, {0, -1, 0}, {0.7071f, -0.7071f, 0}
        };
        const auto &direction = directions[(unsigned(bot->entity->number) + state.sequence) & 7];
        goal = selected ? selected->origin : bot->entity->origin;
        float x = goal.x - bot->entity->origin.x;
        float y = goal.y - bot->entity->origin.y;
        const float extent = __builtin_fabsf(x) > __builtin_fabsf(y) ? __builtin_fabsf(x) : __builtin_fabsf(y);
        if (extent > 2048.0f)
        {
            const float fraction = 2048.0f / extent;
            goal = {bot->entity->origin.x + x * fraction, bot->entity->origin.y + y * fraction,
                    bot->entity->origin.z + (goal.z - bot->entity->origin.z) * fraction};
        }
        const float spread = selected ? 64.0f : 768.0f;
        goal.x += direction.x * spread;
        goal.y += direction.y * spread;
        return __builtin_isfinite(goal.x) && __builtin_isfinite(goal.y) && __builtin_isfinite(goal.z);
    }

    bool FollowMesh(BotNavigationView *bot, UserCmd *command, bool allowPlan)
    {
        auto *nav = bot->navigator;
        auto *entity = bot->entity;
        const unsigned slot = entity ? uint16_t(entity->number) : 200;
        if (slot >= 200 || !bot->sentient || !(bot->scriptFlags & 0x1000000) ||
            !nav ||
            nav->vtable[45] != reinterpret_cast<uintptr_t>(&SVHS_Nav2DClosest) ||
            !nav->currentArea.reference || !*nav->currentArea.reference || !nav->currentArea.space ||
            !bot->playerState || entity->health <= 0 || bot->traversal ||
            Field<uint16_t>(bot->playerState, 626) == 2047 || Locked(bot))
        {
            if (slot < 200)
                s_goals[slot].valid = false;
            return false;
        }

        auto &state = s_goals[slot];
        const int32_t now = SVHS_LevelTime;
        if (state.owner != bot || state.navigator != nav || state.player != bot->playerState || now < state.lastTime)
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
        const bool owned = state.valid && state.owner == bot && state.navigator == nav;
        if (path && !owned)
            return false;
        const bool reached = state.valid && DistanceSquared(entity->origin, state.goal) < 96.0f * 96.0f;
        const bool stuck = now - state.progressTime >= 1500;
        if (allowPlan && now >= state.nextPlan && (!path || reached || stuck || !state.valid) &&
            s_plans < 2 && slot >= s_nextPlanSlot)
        {
            Vec3 goal{};
            ++s_plans;
            s_nextPlanSlot = slot + 1;
            state.nextPlan = now + 1000 + int32_t((slot * 97) % 500);
            state.progressTime = now;
            if (stuck || state.failures >= 2 || (reached && !state.target))
            {
                ++state.sequence;
                state.failures = 0;
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
}

extern "C" unsigned Bot_UpdateMove_OffPathGrid(void *data, HostScale::UserCmd *command)
{
    using namespace HostScale;
    auto *bot = static_cast<BotNavigationView *>(data);
    if (Enabled() && FollowMesh(bot, command, true))
        return 1;
    const bool canFire = SVHS_BotCanFire(data);
    const bool failedLongEnough = bot->noPathFoundTime && SVHS_LevelTime - bot->noPathFoundTime > 750;
    const bool airborneWithoutPath = !SVHS_NavHasPath(bot->navigator) &&
                                    Field<uint16_t>(bot->playerState, 626) == 2047;
    if (canFire || Locked(bot) || (!failedLongEnough && !airborneWithoutPath))
        return 0;
    Vec3 forward{}, right{};
    SVHS_BotYawVectors(Field<float>(bot->playerState, 464), &forward, &right);
    const auto &direction = bot->strafeDirection;
    Field<int8_t>(command, 156) = int8_t(int(((forward.y * direction.y + forward.x * direction.x) + forward.z * direction.z) * 127.0f));
    Field<int8_t>(command, 157) = int8_t(int(((right.y * direction.y + right.x * direction.x) + right.z * direction.z) * 127.0f));
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
    const auto &state = s_goals[slot];
    auto *nav = bot->navigator;
    const bool owned = state.valid && state.owner == bot && state.player == bot->playerState &&
                       state.navigator == nav;
    const bool nativePath = !owned && nav && bot->sentient && bot->playerState &&
        entity->health > 0 && !bot->traversal && !Locked(bot) &&
        Field<uint16_t>(bot->playerState, 626) != 2047 &&
        SVHS_NavHasPath(nav) && !SVHS_BotCanFire(bot);
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
