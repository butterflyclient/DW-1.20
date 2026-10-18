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
};
Batch s_batches[BatchCount];
Slot s_slots[200];
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
    if (active != s_active || (active && (s_statics != SVHS_GameStatics || now < s_time)))
        ResetMap();
    s_active = active;
    s_statics = SVHS_GameStatics;
    s_time = now;
    s_captureEpoch = (uint64_t(s_map) << 32) | uint32_t(now);
    s_graphsThisFrame = 0;
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
                if (result.status == HostBotGpu::Route &&
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
                }
            }
            batch.state = 0;
            Increment(s_stale);
        }
}

bool HostBotPlanner::Pending(unsigned slot)
{
    return Enabled() && slot < 200 && s_slots[slot].state && s_slots[slot].map == s_map;
}
void HostBotPlanner::Cancel(unsigned slot)
{
    if (slot < 200)
    {
        ++s_slots[slot].generation;
        s_slots[slot].state = 0;
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
    if (!slot.state)
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

bool HostBotPlanner::Queue(unsigned index, const void *owner, const void *player,
                           const void *navigator, uint64_t profile, const NavAreaHandle &start,
                           const NavAreaHandle &goal, const NavSearchSpec &spec, const Vec3 &origin,
                           const Vec3 &destination)
{
    if (index >= 200 || !Enabled() || !s_active || !start.space || !AreaIdentity(start))
        return false;
    // A same-polygon move needs no graph search. Let the native planner use
    // the chosen destination rather than returning this polygon's center.
    if (start.space == goal.space && AreaIdentity(start) == AreaIdentity(goal))
        return false;
    if (Current(s_slots[index], owner, player, navigator, profile) &&
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
    batch->requests[batch->count++] = {index,     slot.generation, uint32_t(s_time),
                                       startNode, goalNode,        0};
    Increment(s_queued);
    return true;
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
               "GPU navigation fallback: unsupported graph %u, search budget %u, no route %u, "
               "stale %u; gas routes %u; last GPU %u us; device failures %u; captured nodes %u\n",
               Read(s_unsupported), Read(s_budget), Read(s_unreachable), Read(s_stale), Read(s_gas),
               Read(s_gpuUs), Read(s_gpuFailures), Read(s_nodesCaptured));
}
