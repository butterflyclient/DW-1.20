#include "sv_host_scale.h"
#include "SightDiscoverySchedule.h"
#include <xmmintrin.h>

namespace
{
    using namespace HostScale;
    SightDiscoverySchedule s_discovery;
    SightWorkCounters s_work{};

    struct SightServerClientView
    {
        uint8_t opaque0[8];
        uint8_t state;
        uint8_t opaque9[271];
        Entity *entity;
        uint8_t opaque288[214468];
        int32_t clientKind;
    };
#pragma pack(push, 4)
    struct SightPlayerView
    {
        uint8_t opaque0[12];
        int32_t movementType, movementTime;
        uint64_t movementFlags;
        uint8_t opaque28[22308];
        uint32_t gameExtraInfo;
        uint8_t opaque22340[1676];
        uint32_t freezeFlags;
    };
#pragma pack(pop)
    static_assert(offsetof(SightServerClientView, state) == 8);
    static_assert(offsetof(SightServerClientView, entity) == 280);
    static_assert(offsetof(SightServerClientView, clientKind) == 214756);
    static_assert(offsetof(SightPlayerView, movementFlags) == 20);
    static_assert(offsetof(SightPlayerView, gameExtraInfo) == 22336);
    static_assert(offsetof(SightPlayerView, freezeFlags) == 24016);

    bool CurrentQueuedOwner(unsigned slot, uintptr_t entityIdentity, uintptr_t playerIdentity)
    {
        if (slot >= SVHS_ClientCount || slot >= 200)
            return false;
        const auto *client = static_cast<const SightServerClientView *>(SVHS_Clients[slot]);
        if (!client || client->state < 5 || client->clientKind != 2)
            return false;
        auto *entity = client->entity;
        if (!entity || uintptr_t(entity) != entityIdentity || uint16_t(entity->number) != slot ||
            uintptr_t(entity->client) != playerIdentity || !entity->client || entity->health <= 0)
            return false;
        // These native early-return states do not call the AI sight update.
        const auto *player = reinterpret_cast<const SightPlayerView *>(entity->client);
        return uint32_t(player->movementType) <= 1 && !(player->movementFlags & 0x8000) &&
               !(player->freezeFlags & 4) && (player->gameExtraInfo & 0x600) != 0x200;
    }

    SentientInfo &Info(AICommon *ai, const Sentient *sentient)
    {
        return ai->info[sentient - static_cast<const Sentient *>(SVHS_Sentients)];
    }

    bool Evaluate(AIInterface *self, const SightCandidate &candidate)
    {
        auto *ai = self->ai;
        const int latency = candidate.distanceSquared <= 262144.0f ? 0 : ai->sightLatency;
        const int last = Info(ai, candidate.sentient).lastUpdateTime;
        // Native signed 32-bit comparison, with the original wrapping add.
        if (last && int32_t(uint32_t(last) + uint32_t(latency)) >= SVHS_LevelTime)
            return false;
        auto *other = candidate.sentient->entity;
        const float distanceSquared = ai->maximumSightDistanceSquared;
        const auto getFovZ = reinterpret_cast<float (*)(AIInterface *, Entity *)>(self->vtable[60]);
        const auto getFov = reinterpret_cast<float (*)(AIInterface *, Entity *)>(self->vtable[59]);
        const float fovZ = getFovZ(self, other);
        const float fov = getFov(self, other);
        SVHS_CanSeeEntity(self, other, fov, fovZ, distanceSquared);
        return true;
    }
    bool EvaluateTracked(AIInterface *self, const SightCandidate &candidate, bool urgent)
    {
        const uint32_t before = self->ai->traceCount;
        const uint64_t started = Clock();
        const bool evaluated = Evaluate(self, candidate);
        const uint32_t traceDelta = self->ai->traceCount - before;
        const uint64_t elapsed = Clock() - started;
        if (evaluated)
        {
            __atomic_fetch_add(urgent ? &s_work.urgentEvaluations : &s_work.backgroundEvaluations,
                               uint64_t(1), __ATOMIC_RELAXED);
            __atomic_fetch_add(urgent ? &s_work.urgentNativeTraceDelta : &s_work.backgroundNativeTraceDelta,
                               uint64_t(traceDelta), __ATOMIC_RELAXED);
            __atomic_fetch_add(urgent ? &s_work.urgentClockTicks : &s_work.backgroundClockTicks,
                               elapsed, __ATOMIC_RELAXED);
        }
        return evaluated;
    }
}

// Complete native UpdateSight replacement. It still refreshes threat-sight
// state for every eligible sentient and uses the native visibility cache,
// priority comparator, entity tracing and perfect-information callback.
extern "C" void AICommon_UpdateSight(HostScale::AIInterface *self)
{
    using namespace HostScale;
    TeamFlags teams{};
    auto *ai = self->ai;
    if (SVHS_TeamMode == 1)
    {
        const bool sp = SVHS_SupportsFeature(182);
        const auto *all = static_cast<const TeamFlags *>(
            SVHS_SupportsFeature(182) ? SVHS_AllCombatTeamsSP() : SVHS_AllTeamsMP());
        teams = *all;
        teams.words[4] &= 0xffffffefu;
        if (sp)
            teams.words[0] &= 0xf7ffffffu;
        teams.words[4] &= 0xffffff9fu;
    }
    else
        SVHS_EnemyTeamFlags(&teams, ai->sentient->team);
    if (ai->sentient->neutralSenses &&
        ai->sentient->team == (SVHS_SupportsFeature(182) ? 4u : 0u))
        teams.words[0] |= 0x20000000u;
    if (!(teams.words[0] | teams.words[1] | teams.words[2] | teams.words[3] | teams.words[4]))
        return;

    SightCandidate candidates[272];
    unsigned count = 0;
    bool nearby = false;
    for (auto *sentient = static_cast<Sentient *>(SVHS_FirstSentient(&teams)); sentient;
         sentient = static_cast<Sentient *>(SVHS_NextSentient(sentient, &teams)))
    {
        ai = self->ai;
        auto *entity = sentient->entity;
        if (sentient == ai->sentient || entity->type == 5 || entity->health <= 0)
            continue;
        if (SVHS_SupportsFeature(2) &&
            ((entity->client && Field<int32_t>(entity->client, 21368) != 2) || (entity->flags & 4)))
            continue;
        Vec3 position;
        SVHS_SentientOrigin(sentient, &position);
        ai = self->ai;
        const Vec3 origin = ai->entity->origin;
        const float x = position.x - origin.x;
        const float y = position.y - origin.y;
        const float z = position.z - origin.z;
        const float distanceSquared = (y * y + x * x) + z * z;
        if (distanceSquared == 0.0f)
            continue;
        // Replay uses RSQRTSS for priority and SQRTSS for threat distance.
        const float inverseDistance = _mm_cvtss_f32(_mm_rsqrt_ss(_mm_set_ss(distanceSquared)));
        auto &info = Info(ai, sentient);
        const int32_t age = int32_t(uint32_t(SVHS_LevelTime) - 2u * uint32_t(SVHS_FrameDuration) -
                                    uint32_t(info.lastUpdateTime));
        if (count == 272)
            break; // Native allocation limit; never overrun the stack on corrupt input.
        candidates[count++] = {sentient, float(age > 0 ? age : 0) * inverseDistance, distanceSquared};
        nearby |= distanceSquared <= 262144.0f;
        const float distance = _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(distanceSquared)));
        SVHS_UpdateThreatSight(ai, &info, distance);
    }
    if (count > 1)
        SVHS_Sort(candidates, count, sizeof(SightCandidate), SVHS_CompareSight);

    const unsigned population = Enabled() ? Population() : 0;
    const bool budgeted = population > 20 && SVHS_IsBotEntity(self->ai->entity);
    if (population <= 100)
        s_discovery.Reset();
    const bool sharedBackground = budgeted && population > 100;
    bool human[272]{};
    unsigned evaluations = 0, deferred = 0;
    const uint32_t originalTraceCount = self->ai->traceCount;
    const uint16_t target = self->ai->sentient->targetHandle;
    unsigned focused = count;
    if (budgeted && target)
    {
        // An acquired enemy keeps its normal visibility cadence. Target handles
        // are entity number + 1; do not treat them as sentient-array indexes.
        for (unsigned i = 0; i < count; ++i)
            if (unsigned(uint16_t(candidates[i].sentient->entity->number)) + 1u == target)
            {
                evaluations += sharedBackground ? EvaluateTracked(self, candidates[i], true) :
                                                 Evaluate(self, candidates[i]);
                focused = i;
                break;
            }
    }
    if (sharedBackground)
    {
        // Human candidates remain on the native latency/FOV/visibility path.
        // They cannot wait behind background bot-versus-bot discovery.
        for (unsigned i = 0; i < count; ++i)
        {
            auto *entity = candidates[i].sentient->entity;
            human[i] = entity->client && !SVHS_IsBotEntity(entity);
            if (human[i] && i != focused)
                evaluations += EvaluateTracked(self, candidates[i], true);
        }
    }
    SightDiscoverySchedule::Reservation reservation{};
    if (sharedBackground)
    {
        __atomic_fetch_add(&s_work.sharedCalls, uint64_t(1), __ATOMIC_RELAXED);
        const auto *entity = self->ai->entity;
        reservation = s_discovery.Reserve(uint16_t(entity->number), SVHS_ClientCount, SVHS_LevelTime,
            uintptr_t(SVHS_GameStatics), uintptr_t(entity), uintptr_t(entity->client),
            uintptr_t(self->ai), CurrentQueuedOwner);
        if (reservation.count)
            __atomic_fetch_add(&s_work.admittedVisits, uint64_t(1), __ATOMIC_RELAXED);
    }
    const unsigned budget = sharedBackground ? reservation.count : population > 64 ? 6 : 8;
    unsigned background = 0;
    for (unsigned i = 0; i < count; ++i)
    {
        if (budgeted && (i == focused || human[i]))
            continue;
        if (budgeted && background >= budget)
        {
            if (sharedBackground)
            {
                for (unsigned j = i; j < count; ++j)
                    deferred += j != focused && !human[j];
            }
            else
                deferred = count - i - (focused > i && focused < count ? 1u : 0u);
            break;
        }
        const bool evaluated = sharedBackground ? EvaluateTracked(self, candidates[i], false) :
                                                  Evaluate(self, candidates[i]);
        evaluations += evaluated;
        background += evaluated;
        if (!budgeted && self->ai->traceCount != originalTraceCount &&
            (!SVHS_IsBotEntity(self->ai->entity) || !nearby))
            break;
    }

    if (sharedBackground)
    {
        s_discovery.Finish(reservation, background);
        __atomic_fetch_add(&s_work.backgroundDeferred, uint64_t(deferred), __ATOMIC_RELAXED);
    }

    // Preserve the native sorted-prefix rule even when its radius ordering is
    // surprising. Changing this would alter awareness rather than scheduling.
    const float radius = self->ai->highlyAwareRadius;
    if (radius != 0.0f)
    {
        const auto perfectInfo = reinterpret_cast<void (*)(AIInterface *, Sentient *, uint8_t)>(
            self->vtable[26]);
        for (unsigned i = 0; i < count && radius * radius > candidates[i].distanceSquared; ++i)
            perfectInfo(self, candidates[i].sentient, 18);
    }
    RecordSight(count, evaluations, deferred);
}

// Value-only diagnostics. Inspectors may locate these counters from this getter;
// no native AI, entity, geometry, or visibility pointer escapes through them.
extern "C" void SV_HostSight_GetWork(HostScale::SightWorkCounters *out)
{
    if (!out)
        return;
    out->urgentEvaluations = __atomic_load_n(&s_work.urgentEvaluations, __ATOMIC_RELAXED);
    out->urgentNativeTraceDelta = __atomic_load_n(&s_work.urgentNativeTraceDelta, __ATOMIC_RELAXED);
    out->backgroundEvaluations = __atomic_load_n(&s_work.backgroundEvaluations, __ATOMIC_RELAXED);
    out->backgroundNativeTraceDelta = __atomic_load_n(&s_work.backgroundNativeTraceDelta, __ATOMIC_RELAXED);
    out->backgroundDeferred = __atomic_load_n(&s_work.backgroundDeferred, __ATOMIC_RELAXED);
    out->sharedCalls = __atomic_load_n(&s_work.sharedCalls, __ATOMIC_RELAXED);
    out->admittedVisits = __atomic_load_n(&s_work.admittedVisits, __ATOMIC_RELAXED);
    out->urgentClockTicks = __atomic_load_n(&s_work.urgentClockTicks, __ATOMIC_RELAXED);
    out->backgroundClockTicks = __atomic_load_n(&s_work.backgroundClockTicks, __ATOMIC_RELAXED);
}
