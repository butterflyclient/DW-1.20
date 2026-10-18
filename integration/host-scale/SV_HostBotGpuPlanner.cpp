#include "SV_HostBotGpuPlanner.h"
#include "SV_HostBotGpu.h"
#include "SV_HostNavGraph.h"
#include "com_debugstates.h"
#include "replay_dvar.h"
#include "sv_host_bot_loot.h"
#include <string.h>

namespace
{
using namespace HostScale;
constexpr unsigned BatchCount = 3;
constexpr int32_t ResultLifetime = 500;
struct Batch
{
    NavGraphSnapshot graph;
    HostBotGpu::Request requests[200];
    uint32_t version, count, retired;
    int32_t frame;
    unsigned state; // 0 free, 1 collecting this frame, 2 in flight.
};
struct Slot
{
    const void *owner, *player, *navigator;
    uint64_t profile, areaIdentity, spaceIdentity;
    float transform[16];
    Vec3 origin, destination, waypoint;
    uint32_t generation, map, version;
    int32_t submitted, retryAfter;
    unsigned state; // 0 idle/fallback, 1 pending, 2 ready.
    bool roam;
};
Batch s_batches[BatchCount]{};
Slot s_slots[200];
struct RoamGoal
{
    const void *owner, *player, *navigator;
    uint64_t profile;
    NavSearchSpec spec;
    Vec3 center, scriptGoal, destination;
    float radius;
    uint32_t map, gasGeneration, scriptType, sequence;
    int32_t created, retryAfter, validated;
    unsigned state; // 0 waiting for queue, 1 GPU pending, 2 candidate, 3 installed, 4 fallback.
    bool active, fallbackWaiting, fallbackPermit, awaitingInstallation, validationWaiting,
        repairCandidate;
    const void *fallbackContext;
    int32_t fallbackFrame;
};
RoamGoal s_roam[200];
unsigned s_fallbackCursor, s_fallbacksThisFrame, s_validationCursor, s_validationsThisFrame;
uint32_t s_roamSkipped, s_roamQueued, s_roamCandidates, s_roamAccepted, s_roamFallbacks;
uint32_t s_roamRejected, s_roamCancelled;
uint64_t s_roamValidationTicks;
HostBotGpu::Node s_nodes[HostBotGpu::MaxNodes];
HostBotGpu::Edge s_edges[HostBotGpu::MaxEdges];
HostBotGpu::Result s_results[BatchCount * 200];
dvar_t *s_enabled;
cmd_function_s s_statusCommand{};
unsigned s_initialization, s_map, s_version, s_graphsThisFrame;
void *s_statics;
int32_t s_time = -1;
bool s_active;
uint64_t s_captureEpoch;
uint32_t s_queued, s_solved, s_committed, s_nativeCommits, s_rejected;
uint32_t s_unsupported, s_budget, s_unreachable, s_stale, s_gas;
uint32_t s_pending, s_gpuUs, s_gpuFailures, s_nodesCaptured;
uint64_t s_captureTicks;

void Increment(uint32_t &counter)
{
    __atomic_fetch_add(&counter, 1u, __ATOMIC_RELAXED);
}
uint32_t Read(const uint32_t &counter)
{
    return __atomic_load_n(&counter, __ATOMIC_RELAXED);
}
float DistanceSquared(const Vec3 &a, const Vec3 &b)
{
    const float x = a.x - b.x, y = a.y - b.y, z = a.z - b.z;
    return x * x + y * y + z * z;
}
uint64_t AreaIdentity(const NavAreaHandle &area)
{
    return area.reference ? uint64_t(reinterpret_cast<uintptr_t>(*area.reference)) : 0;
}
bool Current(const Slot &slot, const void *owner, const void *player, const void *nav,
             uint64_t profile)
{
    return slot.map == s_map && slot.owner == owner && slot.player == player &&
           slot.navigator == nav && slot.profile == profile;
}
void ResetMap()
{
    ++s_map;
    for (auto &slot : s_slots)
    {
        ++slot.generation;
        slot.state = 0;
    }
    // In-flight GPU resources retain their own copied data until fences
    // complete. Their identity checks reject results from this old map.
    for (auto &batch : s_batches)
        batch.state = 0;
    for (auto &roam : s_roam)
        roam = {};
    SV_HostBot_ResetGasState();
}
} // namespace

bool HostBotPlanner::Enabled()
{
    return __atomic_load_n(&s_initialization, __ATOMIC_ACQUIRE) == 2 && s_enabled &&
           s_enabled->current.enabled && HostScale::Enabled();
}

void HostBotPlanner::Frame()
{
    if (!Sys_IsMainThread())
        return;
    if (!s_enabled)
    {
        Dvar_BeginPermanentRegistration();
        s_enabled = Dvar_RegisterBool(
            "sv_botGpuNavigation", true, 1,
            "Batch bot portal route searches on the GPU; native navigation validates movement.");
        Dvar_EndPermanentRegistration();
        Cmd_AddCommandInternal("sv_botGpuStatus", PrintStatus, &s_statusCommand);
    }
    if (!s_enabled || !s_enabled->current.enabled ||
        __atomic_load_n(&s_initialization, __ATOMIC_ACQUIRE))
        return;
    __atomic_store_n(&s_initialization, 1u, __ATOMIC_RELEASE);
    // Frontend prewarm occurs before the server owns this backend. After this
    // release-store, only the server thread accesses the DX12 queue or metrics.
    const HostBotGpu::Config config{0, 0, true, 512, 2000, 512.0f};
    const bool ready = HostBotGpu::Initialize(config);
    __atomic_store_n(&s_initialization, ready ? 2u : 3u, __ATOMIC_RELEASE);
    Com_Printf(15, "GPU bot navigation: %s; sv_botGpuStatus reports route/fallback counters\n",
               ready ? "hardware compute ready" : "native CPU fallback (GPU unavailable)");
}

void HostBotPlanner::BeginServerFrame(bool active)
{
    const int32_t now = SVHS_LevelTime;
    // Script goal generation and BotUpdateBots can both enter in one server tick.
    // Never reset admissions or advance graph ownership twice for that tick.
    if (now == s_time && active == s_active && s_statics == SVHS_GameStatics)
    {
        // A same-tick explicit disable still expires all identities. Re-enabling
        // cannot revive a result merely because frame admission is idempotent.
        if (!Enabled())
        {
            for (unsigned i = 0; i < 200; ++i)
                Cancel(i);
            for (auto &batch : s_batches)
                batch.state = 0;
        }
        return;
    }
    if (active != s_active || (active && (s_statics != SVHS_GameStatics || now < s_time)))
        ResetMap();
    s_active = active;
    s_statics = SVHS_GameStatics;
    s_time = now;
    s_captureEpoch = (uint64_t(s_map) << 32) | uint32_t(now);
    s_graphsThisFrame = 0;
    s_fallbacksThisFrame = 0;
    s_validationsThisFrame = 0;
    if (__atomic_load_n(&s_initialization, __ATOMIC_ACQUIRE) < 2)
        return;
    if (!Enabled())
    {
        // Disabling affects both pending and already completed routes. The GPU
        // backend retains its copied resources until their fences retire, but
        // a later re-enable must never revive one of these old decisions.
        for (auto &slot : s_slots)
        {
            if (slot.state)
                ++slot.generation;
            slot.state = 0;
        }
        for (auto &batch : s_batches)
            batch.state = 0;
        for (unsigned i = 0; i < 200; ++i)
            CancelRoam(i);
    }
    const unsigned count = HostBotGpu::Poll(s_results, BatchCount * 200);
    for (unsigned i = 0; i < count; ++i)
    {
        const auto &result = s_results[i];
        Batch *batch = nullptr;
        for (auto &candidate : s_batches)
            if (candidate.state == 2 && candidate.version == result.graphVersion)
                batch = &candidate;
        if (!batch)
            continue;
        ++batch->retired;
        if (result.slot < 200)
        {
            auto &slot = s_slots[result.slot];
            if (slot.state == 1 && slot.map == s_map && slot.generation == result.generation &&
                slot.version == result.graphVersion && uint32_t(slot.submitted) == result.tick)
            {
                slot.state = 0;
                const HostBotGpu::Request *request = nullptr;
                for (unsigned j = 0; j < batch->count; ++j)
                {
                    const auto &candidate = batch->requests[j];
                    if (candidate.slot == result.slot &&
                        candidate.generation == result.generation && candidate.tick == result.tick)
                    {
                        request = &candidate;
                        break;
                    }
                }
                if (request && request->mode == HostBotGpu::RoamMode)
                {
                    auto &roam = s_roam[result.slot];
                    if (roam.active && roam.map == s_map && roam.state == 1 &&
                        result.status == HostBotGpu::Route &&
                        result.destinationNode < batch->graph.nodeCount)
                    {
                        roam.destination = batch->graph.nodes[result.destinationNode].position;
                        roam.state = 2;
                        Increment(s_roamCandidates);
                    }
                    else if (roam.active)
                    {
                        roam.state = 4;
                        roam.retryAfter = now + 1000;
                    }
                }
                else if (result.status == HostBotGpu::Route &&
                         result.firstHop < batch->graph.nodeCount && request)
                {
                    // Reaching the goal polygon must preserve this bot's exact
                    // chosen destination, including distinct goals in one area.
                    slot.waypoint = result.firstHop == request->goalNode
                                        ? slot.destination
                                        : batch->graph.nodes[result.firstHop].position;
                    slot.state = 2;
                    Increment(s_solved);
                }
                else
                {
                    slot.retryAfter = now + 1000;
                    if (result.status == HostBotGpu::BudgetExceeded)
                        Increment(s_budget);
                    else
                        Increment(s_unreachable);
                }
            }
            else
                Increment(s_stale);
        }
        if (batch->retired >= batch->count)
            batch->state = 0;
    }
    const auto metrics = HostBotGpu::GetMetrics();
    __atomic_store_n(&s_pending, metrics.pending, __ATOMIC_RELAXED);
    __atomic_store_n(&s_gpuUs, uint32_t(metrics.lastGpuMicroseconds), __ATOMIC_RELAXED);
    __atomic_store_n(&s_gpuFailures, uint32_t(metrics.deviceFailures + metrics.timeouts),
                     __ATOMIC_RELAXED);
    if (!metrics.enabled)
    {
        for (auto &slot : s_slots)
            slot.state = 0;
        for (auto &batch : s_batches)
            batch.state = 0;
        __atomic_store_n(&s_initialization, 3u, __ATOMIC_RELEASE);
    }
    for (auto &batch : s_batches)
        if (batch.state == 2 && uint32_t(now - batch.frame) > uint32_t(ResultLifetime))
        {
            for (unsigned i = 0; i < batch.count; ++i)
            {
                auto &slot = s_slots[batch.requests[i].slot];
                if (slot.version == batch.version)
                {
                    slot.state = 0;
                    slot.retryAfter = now + 1000;
                    if (slot.roam && s_roam[batch.requests[i].slot].active)
                    {
                        s_roam[batch.requests[i].slot].state = 4;
                        s_roam[batch.requests[i].slot].retryAfter = now + 1000;
                    }
                }
            }
            batch.state = 0;
            Increment(s_stale);
        }
}

bool HostBotPlanner::Pending(unsigned slot)
{
    return Enabled() && slot < 200 && s_slots[slot].state && !s_slots[slot].roam &&
           s_slots[slot].map == s_map;
}
void HostBotPlanner::Cancel(unsigned slot)
{
    if (slot < 200)
    {
        ++s_slots[slot].generation;
        s_slots[slot].state = 0;
        CancelRoam(slot);
    }
}

HostBotPlanner::RouteState HostBotPlanner::Take(unsigned index, const void *owner,
                                                const void *player, const void *navigator,
                                                uint64_t profile, const NavAreaHandle &area,
                                                const Vec3 &origin, Vec3 &waypoint)
{
    if (index >= 200)
        return RouteState::Fallback;
    if (!Enabled())
    {
        Cancel(index);
        return RouteState::Fallback;
    }
    auto &slot = s_slots[index];
    if (!slot.state || slot.roam)
        return RouteState::Fallback;
    const bool unchanged =
        area.space && uint64_t(reinterpret_cast<uintptr_t>(area.space)) == slot.spaceIdentity &&
        AreaIdentity(area) == slot.areaIdentity &&
        !memcmp(static_cast<const uint8_t *>(area.space) + 76, slot.transform,
                sizeof(slot.transform));
    if (!Current(slot, owner, player, navigator, profile) || !unchanged ||
        uint32_t(s_time - slot.submitted) > uint32_t(ResultLifetime) ||
        DistanceSquared(origin, slot.origin) > 256.0f * 256.0f)
    {
        Cancel(index);
        slot.retryAfter = s_time + 1000;
        Increment(s_stale);
        return RouteState::Fallback;
    }
    if (slot.state == 1)
        return RouteState::Pending;
    waypoint = slot.waypoint;
    slot.state = 0;
    if (DistanceSquared(origin, waypoint) > 32.0f * 32.0f)
        return RouteState::Ready;
    slot.retryAfter = s_time + 1000;
    return RouteState::Fallback;
}

static bool QueueGraph(unsigned index, const void *owner, const void *player, const void *navigator,
                       uint64_t profile, const NavAreaHandle &start, const NavAreaHandle &goal,
                       const NavSearchSpec &spec, const Vec3 &origin, const Vec3 &destination,
                       RoamGoal *roam)
{
    if (index >= 200 || !HostBotPlanner::Enabled() || !s_active || !start.space ||
        !AreaIdentity(start))
        return false;
    if (!roam && s_slots[index].roam && s_slots[index].state)
        return false; // Do not replace a pending BR destination with a movement request.
    // A same-polygon move needs no graph search. Let the native planner use
    // the chosen destination rather than returning this polygon's center.
    if (!roam && start.space == goal.space && AreaIdentity(start) == AreaIdentity(goal))
        return false;
    if (!roam && Current(s_slots[index], owner, player, navigator, profile) &&
        s_time < s_slots[index].retryAfter)
        return false;
    Batch *batch = nullptr;
    uint32_t startNode = ~0u, goalNode = ~0u;
    for (auto &candidate : s_batches)
    {
        if (candidate.state != 1 || candidate.frame != s_time || candidate.count >= 200 ||
            memcmp(&candidate.graph.specification, &spec, sizeof(spec)))
            continue;
        startNode = FindNavGraphNode(candidate.graph, start, s_captureEpoch);
        goalNode = FindNavGraphNode(candidate.graph, goal, s_captureEpoch);
        if (startNode != ~0u && goalNode != ~0u)
        {
            batch = &candidate;
            break;
        }
    }
    if (!batch)
    {
        if (s_graphsThisFrame >= 2)
            return false;
        for (auto &candidate : s_batches)
            if (!candidate.state)
            {
                batch = &candidate;
                break;
            }
        if (!batch)
            return false;
        ++s_graphsThisFrame;
        const uint64_t begin = Clock();
        const auto result = GatherNavGraph(start, goal, spec, s_captureEpoch, batch->graph);
        __atomic_fetch_add(&s_captureTicks, Clock() - begin, __ATOMIC_RELAXED);
        if (result != NavGraphResult::Ready)
        {
            Increment(s_unsupported);
            return false;
        }
        __atomic_fetch_add(&s_nodesCaptured, batch->graph.nodeCount, __ATOMIC_RELAXED);
        batch->version = ++s_version;
        batch->count = batch->retired = 0;
        batch->frame = s_time;
        batch->state = 1;
        startNode = batch->graph.startNode;
        goalNode = batch->graph.goalNode;
    }
    auto &slot = s_slots[index];
    ++slot.generation;
    slot.owner = owner;
    slot.player = player;
    slot.navigator = navigator;
    slot.profile = profile;
    slot.map = s_map;
    slot.version = batch->version;
    slot.submitted = s_time;
    slot.origin = origin;
    slot.destination = destination;
    slot.areaIdentity = AreaIdentity(start);
    slot.spaceIdentity = uint64_t(reinterpret_cast<uintptr_t>(start.space));
    memcpy(slot.transform, static_cast<const uint8_t *>(start.space) + 76, sizeof(slot.transform));
    slot.state = 1;
    slot.roam = roam != nullptr;
    batch->requests[batch->count++] = {index,     slot.generation, uint32_t(s_time),
                                       startNode, goalNode,        0};
    if (roam)
    {
        roam->repairCandidate = false;
        auto &request = batch->requests[batch->count - 1];
        request.mode = HostBotGpu::RoamMode;
        request.seed =
            uint32_t(profile) ^ uint32_t(profile >> 32) ^ (++roam->sequence * 0x9e3779b9u);
        request.goalNode = HostBotGpu::InvalidNode;
        request.circleX = roam->center.x;
        request.circleY = roam->center.y;
        request.circleRadius = roam->radius;
        request.minDistance = HostBotGpu::MinimumRoamDistance;
        request.originX = origin.x;
        request.originY = origin.y;
        request.originZ = origin.z;
        Increment(s_roamQueued);
    }
    Increment(s_queued);
    return true;
}

bool HostBotPlanner::Queue(unsigned index, const void *owner, const void *player,
                           const void *navigator, uint64_t profile, const NavAreaHandle &start,
                           const NavAreaHandle &goal, const NavSearchSpec &spec, const Vec3 &origin,
                           const Vec3 &destination)
{
    return QueueGraph(index, owner, player, navigator, profile, start, goal, spec, origin,
                      destination, nullptr);
}

void HostBotPlanner::CancelRoam(unsigned index)
{
    if (index >= 200)
        return;
    if (s_roam[index].active)
        Increment(s_roamCancelled);
    s_roam[index] = {};
    if (s_slots[index].roam)
    {
        ++s_slots[index].generation;
        s_slots[index].state = 0;
        s_slots[index].roam = false;
    }
}

HostBotPlanner::RouteState HostBotPlanner::RequestRoam(
    unsigned index, const void *owner, const void *player, const void *navigator, uint64_t profile,
    const NavAreaHandle &area, const NavSearchSpec &spec, const Vec3 &origin, const Vec3 &center,
    float radius, uint32_t gasGeneration, uint32_t scriptType, const Vec3 &scriptGoal, bool hasPath,
    Vec3 &destination)
{
    if (index >= 200)
        return RouteState::Fallback;
    if (Enabled() && (SVHS_LevelTime != s_time || !s_active || s_statics != SVHS_GameStatics))
    {
        // VM threads run outside BotUpdateBots. Submit a prior script-only batch
        // before opening the new capture epoch, regardless of native frame order.
        if (s_active && SVHS_LevelTime > s_time && s_statics == SVHS_GameStatics)
            EndServerFrame();
        BeginServerFrame(true);
    }
    if (!Enabled() || !s_active)
    {
        CancelRoam(index);
        return RouteState::Fallback; // GPU off retains the pre-existing host-scale behavior.
    }
    auto &roam = s_roam[index];
    // Hold the submitted circle snapshot through ordinary interpolation. The
    // latest exact circle is checked again before native acceptance below.
    const float circleTolerance = roam.radius * 0.05f > 64.0f ? roam.radius * 0.05f : 64.0f;
    const float radiusTolerance = roam.radius * 0.125f > 256.0f ? roam.radius * 0.125f : 256.0f;
    const float radiusDelta = radius - roam.radius;
    const bool compatibleCircle =
        DistanceSquared(center, roam.center) <= circleTolerance * circleTolerance &&
        radiusDelta >= -radiusTolerance && radiusDelta <= radiusTolerance;
    const bool same =
        roam.active && roam.owner == owner && roam.player == player &&
        roam.navigator == navigator && roam.profile == profile && roam.map == s_map &&
        roam.gasGeneration == gasGeneration && !memcmp(&roam.spec, &spec, sizeof(spec)) &&
        compatibleCircle &&
        (roam.state == 3 ? (DistanceSquared(scriptGoal, roam.destination) <= 1.0f &&
                            (roam.awaitingInstallation || scriptType == roam.scriptType))
                         : (scriptType == roam.scriptType &&
                            DistanceSquared(scriptGoal, roam.scriptGoal) <= 1.0f));
    if (!same)
    {
        const unsigned sequence = roam.sequence;
        CancelRoam(index);
        roam.owner = owner;
        roam.player = player;
        roam.navigator = navigator;
        roam.profile = profile;
        roam.map = s_map;
        roam.gasGeneration = gasGeneration;
        roam.spec = spec;
        roam.center = center;
        roam.radius = radius;
        roam.scriptType = scriptType;
        roam.scriptGoal = scriptGoal;
        roam.created = s_time;
        roam.sequence = sequence;
        roam.active = true;
    }
    if (roam.state == 3)
    {
        if (roam.awaitingInstallation)
        {
            roam.scriptType = scriptType;
            roam.awaitingInstallation = false;
        }
        const float goalX = roam.destination.x - center.x, goalY = roam.destination.y - center.y;
        const bool safe = goalX * goalX + goalY * goalY <= radius * radius;
        if (!safe || DistanceSquared(origin, roam.destination) <= 1024.0f * 1024.0f)
        {
            // A gradually shrinking circle can cross the installed destination
            // before snapshot tolerance is exceeded. Refresh immediately, while
            // the native controller keeps its existing path until acceptance.
            roam.state = 0;
            roam.created = s_time;
            roam.center = center;
            roam.radius = radius;
            roam.scriptGoal = scriptGoal;
            roam.scriptType = scriptType;
        }
        else if (!hasPath && s_time >= roam.retryAfter)
        {
            // The bot may have crossed many polygons since acceptance. Retain
            // only the destination value, and validate against its live area now.
            auto &slot = s_slots[index];
            ++slot.generation;
            slot.state = 0;
            slot.roam = true;
            slot.areaIdentity = AreaIdentity(area);
            slot.spaceIdentity = uint64_t(reinterpret_cast<uintptr_t>(area.space));
            if (area.space)
                memcpy(slot.transform, static_cast<const uint8_t *>(area.space) + 76,
                       sizeof(slot.transform));
            slot.origin = origin;
            roam.created = s_time;
            roam.state = 2;
            roam.repairCandidate = true;
        }
        else
        {
            Increment(s_roamSkipped);
            return RouteState::Pending;
        }
    }
    if (roam.state == 1 || roam.state == 2)
    {
        const bool candidateReady = roam.state == 2;
        const auto &slot = s_slots[index];
        const bool unchanged =
            slot.roam && (candidateReady || slot.state) &&
            uint64_t(reinterpret_cast<uintptr_t>(area.space)) == slot.spaceIdentity &&
            AreaIdentity(area) == slot.areaIdentity && area.space &&
            !memcmp(static_cast<const uint8_t *>(area.space) + 76, slot.transform,
                    sizeof(slot.transform)) &&
            DistanceSquared(origin, slot.origin) <= 256.0f * 256.0f;
        // A copied value candidate can wait for its fair native-validation turn.
        // Account for the entire roster at two admissions/tick, plus one second.
        const unsigned frame = SVHS_FrameDuration > 50 ? unsigned(SVHS_FrameDuration) : 50u;
        const unsigned boundedFrame = frame < 200 ? frame : 200;
        const unsigned roster = SVHS_ClientCount < 200 ? SVHS_ClientCount : 200;
        const unsigned drainLifetime = ((roster + 1) / 2) * boundedFrame + 1000;
        const unsigned candidateLifetime = drainLifetime > 4000 ? drainLifetime : 4000;
        if (!unchanged || uint32_t(s_time - roam.created) >
                              (candidateReady ? candidateLifetime : uint32_t(ResultLifetime)))
        {
            if (slot.roam)
            {
                ++s_slots[index].generation;
                s_slots[index].state = 0;
            }
            roam.state = 4;
            roam.retryAfter = s_time + 1000;
        }
        else if (!candidateReady)
        {
            Increment(s_roamSkipped);
            return RouteState::Pending;
        }
    }
    if (roam.state == 2)
    {
        roam.validationWaiting = true;
        destination = roam.destination;
        return RouteState::Ready;
    }
    if (roam.state == 0 && area.space && AreaIdentity(area) &&
        QueueGraph(index, owner, player, navigator, profile, area, area, spec, origin, origin,
                   &roam))
    {
        roam.state = 1;
        roam.created = s_time;
        Increment(s_roamSkipped);
        return RouteState::Pending;
    }
    if (roam.state == 0 && s_time - roam.created >= 1000)
    {
        roam.state = 4;
        roam.retryAfter = s_time;
    }
    if (roam.state == 4 && s_time >= roam.retryAfter)
    {
        roam.fallbackWaiting = true;
        // Two native goal chains per server frame, rotating over waiting owners.
        // A caller earlier in the script order keeps its ticket for the next frame.
        unsigned selected = 200;
        for (unsigned i = 0; i < 200; ++i)
        {
            const unsigned candidate = (s_fallbackCursor + i) % 200;
            if (s_roam[candidate].active && s_roam[candidate].fallbackWaiting)
            {
                selected = candidate;
                break;
            }
        }
        if (s_fallbacksThisFrame < 2 && selected == index)
        {
            ++s_fallbacksThisFrame;
            s_fallbackCursor = (index + 1) % 200;
            roam.fallbackWaiting = false;
            roam.retryAfter = s_time + 1000;
            roam.fallbackPermit = true;
            roam.fallbackFrame = s_time;
            roam.fallbackContext = nullptr;
            Increment(s_roamFallbacks);
            return RouteState::Fallback;
        }
    }
    Increment(s_roamSkipped);
    return RouteState::Pending;
}

void HostBotPlanner::BindNativeRoamFallback(unsigned index, const void *owner, const void *player,
                                            const void *navigator, const void *context)
{
    if (index >= 200 || !context)
        return;
    auto &roam = s_roam[index];
    if (roam.active && roam.fallbackPermit && roam.map == s_map && roam.fallbackFrame == s_time &&
        roam.owner == owner && roam.player == player && roam.navigator == navigator)
        roam.fallbackContext = context;
}
bool HostBotPlanner::ConsumeNativeRoamFallback(unsigned index, const void *player,
                                               const void *navigator, const void *context)
{
    if (index >= 200 || !context)
        return false;
    auto &roam = s_roam[index];
    if (!Enabled() || !roam.active || !roam.fallbackPermit || roam.map != s_map ||
        roam.fallbackFrame != SVHS_LevelTime || roam.player != player ||
        roam.navigator != navigator || roam.fallbackContext != context)
        return false;
    roam.fallbackPermit = false;
    roam.fallbackContext = nullptr;
    return true;
}

bool HostBotPlanner::RoamCandidateAllowed(const Vec3 &origin, const Vec3 &destination,
                                          const Vec3 &center, float insetRadius, bool newGoal)
{
    const float x = destination.x - center.x, y = destination.y - center.y;
    return __builtin_isfinite(destination.x) && __builtin_isfinite(destination.y) &&
           __builtin_isfinite(destination.z) && __builtin_isfinite(insetRadius) &&
           insetRadius > 0 &&
           DistanceSquared(origin, destination) >
               (newGoal ? HostBotGpu::MinimumRoamDistance * HostBotGpu::MinimumRoamDistance
                        : 1024.0f * 1024.0f) &&
           x * x + y * y <= insetRadius * insetRadius;
}

bool HostBotPlanner::RoamRepair(unsigned index)
{
    return index < 200 && s_roam[index].active && s_roam[index].state == 2 &&
           s_roam[index].repairCandidate;
}

bool HostBotPlanner::AdmitRoamValidation(unsigned index)
{
    if (index >= 200 || !s_roam[index].active || s_roam[index].state != 2 ||
        !s_roam[index].validationWaiting || s_validationsThisFrame >= 2)
    {
        Increment(s_roamSkipped);
        return false;
    }
    for (unsigned i = 0; i < 200; ++i)
    {
        const unsigned candidate = (s_validationCursor + i) % 200;
        if (!s_roam[candidate].active || s_roam[candidate].state != 2 ||
            !s_roam[candidate].validationWaiting)
            continue;
        if (candidate != index)
        {
            Increment(s_roamSkipped);
            return false;
        }
        ++s_validationsThisFrame;
        s_validationCursor = (index + 1) % 200;
        s_roam[index].validationWaiting = false;
        return true;
    }
    Increment(s_roamSkipped);
    return false;
}

void HostBotPlanner::FinishRoam(unsigned index, bool accepted, const Vec3 *destination)
{
    if (index >= 200 || !s_roam[index].active)
        return;
    auto &roam = s_roam[index];
    if (accepted && destination)
        roam.destination = *destination;
    roam.state = accepted ? 3u : 4u;
    roam.awaitingInstallation = accepted;
    roam.validationWaiting = false;
    roam.retryAfter = s_time + 1000;
    roam.validated = s_time;
    Increment(accepted ? s_roamAccepted : s_roamRejected);
}
void HostBotPlanner::RecordRoamValidation(uint64_t ticks)
{
    __atomic_fetch_add(&s_roamValidationTicks, ticks, __ATOMIC_RELAXED);
}

void HostBotPlanner::EndServerFrame()
{
    if (__atomic_load_n(&s_initialization, __ATOMIC_ACQUIRE) != 2)
        return;
    BotGasState gas{};
    const bool hasGas = SV_HostBot_GetGasState(&gas);
    const Vec3 center = gas.closing ? gas.nextCenter : gas.currentCenter;
    const float radius = gas.closing ? gas.nextRadius : gas.currentRadius;
    for (auto &batch : s_batches)
    {
        if (batch.state != 1)
            continue;
        for (unsigned i = 0; i < batch.graph.nodeCount; ++i)
        {
            const auto &node = batch.graph.nodes[i];
            s_nodes[i] = {node.position.x, node.position.y, node.position.z,
                          node.firstEdge,  node.edgeCount,  0};
            for (unsigned e = node.firstEdge; e < node.firstEdge + node.edgeCount; ++e)
            {
                const auto &edge = batch.graph.edges[e];
                float cost = edge.cost;
                if (hasGas && radius > 0)
                {
                    const float x = edge.portal.x - center.x, y = edge.portal.y - center.y;
                    const float outside = __builtin_sqrtf(x * x + y * y) - radius;
                    if (outside > 0)
                        cost *= 1.0f + 8.0f * outside / radius;
                }
                s_edges[e] = {edge.destination, cost, 0};
            }
        }
        const HostBotGpu::Graph graph{s_nodes, s_edges, batch.graph.nodeCount,
                                      batch.graph.edgeCount, batch.version};
        if (Enabled() && HostBotGpu::Submit(graph, batch.requests, batch.count))
            batch.state = 2;
        else
        {
            for (unsigned i = 0; i < batch.count; ++i)
            {
                auto &slot = s_slots[batch.requests[i].slot];
                if (slot.version == batch.version)
                {
                    slot.state = 0;
                    slot.retryAfter = s_time + 1000;
                    if (slot.roam && s_roam[batch.requests[i].slot].active)
                    {
                        s_roam[batch.requests[i].slot].state = 4;
                        s_roam[batch.requests[i].slot].retryAfter = s_time + 1000;
                    }
                }
            }
            batch.state = 0;
        }
    }
}

void HostBotPlanner::RecordCommit(bool gpu, bool success, bool gas)
{
    Increment(success ? (gpu ? s_committed : s_nativeCommits) : s_rejected);
    if (success && gas)
        Increment(s_gas);
}
void HostBotPlanner::PrintStatus()
{
    Com_Printf(15,
               "GPU navigation: %s; queued %u solved %u committed %u; native %u; rejected %u; "
               "pending batches %u\n",
               Enabled() ? "enabled" : "CPU fallback/off", Read(s_queued), Read(s_solved),
               Read(s_committed), Read(s_nativeCommits), Read(s_rejected), Read(s_pending));
    Com_Printf(15,
               "GPU BR roam: skipped %u queued %u candidates %u accepted %u rejected %u native "
               "fallback %u cancelled %u validation ticks %llu\n",
               Read(s_roamSkipped), Read(s_roamQueued), Read(s_roamCandidates),
               Read(s_roamAccepted), Read(s_roamRejected), Read(s_roamFallbacks),
               Read(s_roamCancelled), __atomic_load_n(&s_roamValidationTicks, __ATOMIC_RELAXED));
    Com_Printf(15,
               "GPU navigation fallback: unsupported graph %u, search budget %u, no route %u, "
               "stale %u; gas routes %u; last GPU %u us; device failures %u; captured nodes %u\n",
               Read(s_unsupported), Read(s_budget), Read(s_unreachable), Read(s_stale), Read(s_gas),
               Read(s_gpuUs), Read(s_gpuFailures), Read(s_nodesCaptured));
}

// Value-only read boundary. Inspectors may derive RIP-relative source loads and
// fixed destination offsets without calling into the live game process.
extern "C" void SV_HostBotGpu_GetPlannerWork(HostBotPlanner::PlannerWork *out)
{
    if (!out)
        return;
    out->queued = __atomic_load_n(&s_queued, __ATOMIC_RELAXED);
    out->solved = __atomic_load_n(&s_solved, __ATOMIC_RELAXED);
    out->committed = __atomic_load_n(&s_committed, __ATOMIC_RELAXED);
    out->nativeCommits = __atomic_load_n(&s_nativeCommits, __ATOMIC_RELAXED);
    out->rejected = __atomic_load_n(&s_rejected, __ATOMIC_RELAXED);
    out->unsupported = __atomic_load_n(&s_unsupported, __ATOMIC_RELAXED);
    out->searchBudget = __atomic_load_n(&s_budget, __ATOMIC_RELAXED);
    out->unreachable = __atomic_load_n(&s_unreachable, __ATOMIC_RELAXED);
    out->stale = __atomic_load_n(&s_stale, __ATOMIC_RELAXED);
    out->gasRoutes = __atomic_load_n(&s_gas, __ATOMIC_RELAXED);
    out->pendingBatches = __atomic_load_n(&s_pending, __ATOMIC_RELAXED);
    out->lastGpuMicroseconds = __atomic_load_n(&s_gpuUs, __ATOMIC_RELAXED);
    out->gpuFailures = __atomic_load_n(&s_gpuFailures, __ATOMIC_RELAXED);
    out->capturedNodes = __atomic_load_n(&s_nodesCaptured, __ATOMIC_RELAXED);
    out->roamCoalesced = __atomic_load_n(&s_roamSkipped, __ATOMIC_RELAXED);
    out->roamQueued = __atomic_load_n(&s_roamQueued, __ATOMIC_RELAXED);
    out->roamCandidates = __atomic_load_n(&s_roamCandidates, __ATOMIC_RELAXED);
    out->roamAccepted = __atomic_load_n(&s_roamAccepted, __ATOMIC_RELAXED);
    out->roamRejected = __atomic_load_n(&s_roamRejected, __ATOMIC_RELAXED);
    out->roamNativeFallbacks = __atomic_load_n(&s_roamFallbacks, __ATOMIC_RELAXED);
    out->roamCancelled = __atomic_load_n(&s_roamCancelled, __ATOMIC_RELAXED);
    out->roamValidationTicks = __atomic_load_n(&s_roamValidationTicks, __ATOMIC_RELAXED);
    out->captureTicks = __atomic_load_n(&s_captureTicks, __ATOMIC_RELAXED);
}
