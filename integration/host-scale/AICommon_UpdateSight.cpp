#include "sv_host_scale.h"
#include <xmmintrin.h>

namespace
{
    using namespace HostScale;

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
                evaluations += Evaluate(self, candidates[i]);
                focused = i;
                break;
            }
    }
    const unsigned budget = population > 100 ? 4 : population > 64 ? 6 : 8;
    unsigned background = 0;
    for (unsigned i = 0; i < count; ++i)
    {
        if (budgeted && i == focused)
            continue;
        if (budgeted && background >= budget)
        {
            deferred = count - i - (focused > i && focused < count ? 1u : 0u);
            break;
        }
        const bool evaluated = Evaluate(self, candidates[i]);
        evaluations += evaluated;
        background += evaluated;
        if (!budgeted && self->ai->traceCount != originalTraceCount &&
            (!SVHS_IsBotEntity(self->ai->entity) || !nearby))
            break;
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
