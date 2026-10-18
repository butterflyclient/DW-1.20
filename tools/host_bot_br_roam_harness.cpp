// Actual coordinator with modeled graph/GPU boundaries; no game process.
#define main ExistingCoordinatorMain
#include "host_bot_gpu_planner_harness.cpp"
#undef main
using HostBotPlanner::RouteState;
static HostScale::Vec3 circle{0, 0, 0}, output{}, installed{};
static RouteState Roam(unsigned slot, bool path = false, const HostScale::Vec3 &goal = installed,
                       uint64_t profile = 77, uint32_t gas = 1)
{
    return HostBotPlanner::RequestRoam(slot, Fixture::Owner(slot), Fixture::Player(slot),
                                       Fixture::Nav(slot), profile, Fixture::start, Fixture::spec,
                                       Fixture::origin, circle, 4000, gas, 1, goal, path, output);
}
static void CompleteRoam(unsigned status = HostBotGpu::Route)
{
    Fixture::Complete(static_cast<HostBotGpu::Status>(status));
    for (unsigned i = 0; i < Fixture::resultCount; ++i)
        Fixture::results[i].destinationNode = 2;
}
int main()
{
    using namespace Fixture;
    ExistingCoordinatorMain();
    metrics.enabled = 1;
    toggleDvar->current.enabled = true;
    s_initialization = 2;
    for (unsigned i = 0; i < 200; ++i)
        HostBotPlanner::Cancel(i);
    SVHS_LevelTime += 100;
    HostBotPlanner::BeginServerFrame(true);
    const unsigned before = captures;
    for (unsigned i = 0; i < 200; ++i)
        Require(Roam(i) == RouteState::Pending, "200 roam requests pending");
    Require(captures == before + 1, "one copied graph for200 roam owners");
    for (unsigned i = 0; i < 200; ++i)
    {
        Require(!HostBotPlanner::Pending(i), "route pending excludes roam");
        Require(Roam(i) == RouteState::Pending, "duplicate coalesced");
    }
    HostBotPlanner::EndServerFrame();
    Require(submittedCount == 200, "all roam batched");
    for (unsigned i = 0; i < 200; ++i)
        Require(requests[i].mode == HostBotGpu::RoamMode &&
                    requests[i].goalNode == HostBotGpu::InvalidNode &&
                    requests[i].minDistance == 1056,
                "typed roam request ABI");
    CompleteRoam();
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    Require(Roam(0) == RouteState::Ready && output.x == 1200,
            "selected destination not first hop600");
    Require(Roam(0) == RouteState::Ready, "candidate retained before validation admission");
    installed = output;
    HostBotPlanner::FinishRoam(0, true, &installed);
    Require(Roam(0, true) == RouteState::Pending, "installed goal retained");
    Require(Roam(0, false) == RouteState::Pending, "no-path does not randomize during cooldown");
    SVHS_LevelTime += 1001;
    HostBotPlanner::BeginServerFrame(true);
    origin = {0, 300, 0};
    start.reference = &areas[1];
    Require(Roam(0, false) == RouteState::Ready && output.x == 1200,
            "lost path retries same stable goal");
    HostBotPlanner::FinishRoam(0, false);
    origin = {};
    start.reference = &areas[0];
    Require(Roam(0, false) == RouteState::Pending, "rejected native validation backoff");
    HostBotPlanner::CancelRoam(1);
    Require(!s_roam[1].active, "explicit phase cancellation");
    Require(Roam(1) == RouteState::Pending, "new generation after cancellation");
    const unsigned oldGeneration = s_slots[1].generation;
    Require(Roam(1, false, installed, 78) == RouteState::Pending &&
                s_slots[1].generation > oldGeneration,
            "profile reuse invalidates pending result");
    const unsigned gasGeneration = s_slots[1].generation;
    Require(Roam(1, false, installed, 78, 2) == RouteState::Pending &&
                s_slots[1].generation > gasGeneration,
            "gas generation cancels pending request");
    const unsigned specGeneration = s_slots[1].generation;
    spec.obstacleFlags = 4;
    Require(Roam(1, false, installed, 78, 2) == RouteState::Pending &&
                s_slots[1].generation > specGeneration,
            "full native spec change cancels pending request");
    spec.obstacleFlags = 0;
    HostBotPlanner::CancelRoam(2);
    Require(Roam(2) == RouteState::Pending, "queue circle test");
    circle.x = 512;
    Require(Roam(2) == RouteState::Pending && s_roam[2].center.x == 512,
            "circle change cancels old generation");
    circle.x = 0;

    SVHS_GameStatics = reinterpret_cast<void *>(0x92000);
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    HostBotPlanner::CancelRoam(3);
    Require(Roam(3) == RouteState::Pending, "queue gradual shrink");
    HostBotPlanner::EndServerFrame();
    CompleteRoam();
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    const unsigned shrinkGeneration = s_slots[3].generation;
    for (unsigned i = 0; i < 15; ++i)
    {
        SVHS_LevelTime += 50;
        HostBotPlanner::BeginServerFrame(true);
        Require(HostBotPlanner::RequestRoam(3, Owner(3), Player(3), Nav(3), 77, start, spec, origin,
                                            circle, 4000 - float(i) * 16, 1, 1, installed, false,
                                            output) == RouteState::Ready,
                "gradual shrink retains candidate");
        Require(s_slots[3].generation == shrinkGeneration, "gradual shrink does not requeue");
    }
    Require(HostBotPlanner::RoamCandidateAllowed(origin, {3900, 0, 0}, circle, 4000),
            "candidate safe in submitted circle");
    Require(!HostBotPlanner::RoamCandidateAllowed(origin, {3900, 0, 0}, circle, 3800),
            "latest shrink rejects unsafe candidate");
    Require(!HostBotPlanner::RoamCandidateAllowed(origin, {1056, 0, 0}, circle, 4000),
            "strict reached-radius margin");
    for (unsigned i = 0; i < 200; ++i)
        HostBotPlanner::Cancel(i);
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    for (unsigned i = 0; i < 200; ++i)
        Require(Roam(i) == RouteState::Pending, "queue no eligible test");
    HostBotPlanner::EndServerFrame();
    CompleteRoam(HostBotGpu::NoEligible);
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    Require(Roam(0) == RouteState::Pending, "no eligible backoff");
    SVHS_LevelTime += 1000;
    bool served[200]{};
    unsigned total = 0;
    for (unsigned frame = 0; frame < 100; ++frame)
    {
        ++SVHS_LevelTime;
        HostBotPlanner::BeginServerFrame(true);
        unsigned admitted = 0;
        for (unsigned i = 0; i < 200; ++i)
            if (Roam(i) == RouteState::Fallback)
            {
                ++admitted;
                if (!served[i])
                {
                    served[i] = true;
                    ++total;
                }
                const void *context = reinterpret_cast<void *>(0x4444);
                HostBotPlanner::BindNativeRoamFallback(i, Owner(i), Player(i), Nav(i), context);
                Require(!HostBotPlanner::ConsumeNativeRoamFallback(
                            i, Player(i), Nav(i), reinterpret_cast<void *>(0x5555)),
                        "wrong VM cannot consume fallback");
                Require(!HostBotPlanner::ConsumeNativeRoamFallback(
                            i, Player(i), reinterpret_cast<void *>(0x8888), context),
                        "wrong navigator cannot consume fallback");
                Require(HostBotPlanner::ConsumeNativeRoamFallback(i, Player(i), Nav(i), context),
                        "exact owner VM fallback consumes");
                Require(!HostBotPlanner::ConsumeNativeRoamFallback(i, Player(i), Nav(i), context),
                        "fallback permit one use");
            }
        Require(admitted <= 2, "native fallback cap2 perframe");
    }
    Require(total == 200, "rotating fallback serves all200 owners");
    toggleDvar->current.enabled = false;
    for (unsigned i = 0; i < 200; ++i)
        Require(Roam(i) == RouteState::Fallback, "GPU off stock fallback unchanged");
    toggleDvar->current.enabled = true;
    metrics.enabled = 1;
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    Require(Roam(4) == RouteState::Pending, "map lifecycle queue");
    SVHS_GameStatics = reinterpret_cast<void *>(0x99000);
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    Require(!s_roam[4].active, "map reset discards value state");
    Require(Roam(5) == RouteState::Pending, "script after BotUpdate queues");
    const unsigned oldSubmits = submits;
    SVHS_LevelTime += 50;
    Require(Roam(5) == RouteState::Pending && submits == oldSubmits + 1,
            "next VM frame flushes previous script-only batch");
    s_fallbacksThisFrame = 2;
    HostBotPlanner::BeginServerFrame(true);
    Require(s_fallbacksThisFrame == 2, "same-frame Begin cannot reset admission");
    toggleDvar->current.enabled = false;
    HostBotPlanner::BeginServerFrame(true);
    toggleDvar->current.enabled = true;
    HostBotPlanner::BeginServerFrame(true);
    Require(!s_roam[5].active, "same-frame off-on cannot revive roam state");
    SVHS_LevelTime = 1;
    HostBotPlanner::BeginServerFrame(true);
    Require(!s_roam[5].active, "time rewind resets request generation");
    // A newly ready low slot cannot jump ahead of older high-slot tickets.
    SVHS_GameStatics = reinterpret_cast<void *>(0x9A000);
    SVHS_FrameDuration = 100;
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    for (unsigned i = 0; i < 200; ++i)
        Require(Roam(i) == RouteState::Pending, "queue fair validation roster");
    HostBotPlanner::EndServerFrame();
    CompleteRoam();
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    for (unsigned i = 0; i < 200; ++i)
        Require(Roam(i) == RouteState::Ready, "register all validation tickets");
    bool validated[200]{};
    unsigned validatedOwners = 0;
    for (unsigned frame = 0; frame < 100; ++frame)
    {
        SVHS_LevelTime += 100;
        HostBotPlanner::BeginServerFrame(true);
        unsigned admitted = 0;
        // Model new GPU-ready tickets from the earliest script owners.
        for (unsigned i = 0; i < 2; ++i)
            if (validated[i])
            {
                s_roam[i].state = 2;
                s_roam[i].validationWaiting = true;
            }
        for (unsigned i = 0; i < 200; ++i)
            if (Roam(i, true) == RouteState::Ready && HostBotPlanner::AdmitRoamValidation(i))
            {
                ++admitted;
                if (!validated[i])
                {
                    validated[i] = true;
                    ++validatedOwners;
                }
                HostBotPlanner::FinishRoam(i, true, &installed);
            }
        Require(admitted <= 2, "native validation admission cap");
    }
    Require(validatedOwners == 200, "rotating validation serves all200 at100ms without expiry");
    SVHS_GameStatics = reinterpret_cast<void *>(0x9B000);
    SVHS_FrameDuration = 50;
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    auto radiusRequest = [&](float radius, bool path) {
        return HostBotPlanner::RequestRoam(6, Owner(6), Player(6), Nav(6), 77, start, spec, origin,
                                           circle, radius, 1, 1, installed, path, output);
    };
    Require(radiusRequest(1400, false) == RouteState::Pending, "queue installed circle edge");
    HostBotPlanner::EndServerFrame();
    CompleteRoam();
    ++SVHS_LevelTime;
    HostBotPlanner::BeginServerFrame(true);
    Require(radiusRequest(1400, false) == RouteState::Ready, "accept circle edge goal");
    HostBotPlanner::FinishRoam(6, true, &installed);
    Require(radiusRequest(1150, true) == RouteState::Pending && s_roam[6].state == 1 &&
                s_roam[6].radius == 1150,
            "gradual shrink across installed goal boundary requeues despite existing path");
    Require(HostBotPlanner::RoamCandidateAllowed(origin, {1050, 0, 0}, circle, 4000, false),
            "existing goal repair does not reapply new-candidate1056 margin");
    Require(!HostBotPlanner::RoamCandidateAllowed(origin, {1050, 0, 0}, circle, 4000, true),
            "new goal retains1056 margin");
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::None) == 0);
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::Hunt) == 1);
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::Guard) == 2);
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::Camp) == 3);
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::Objective) == 4);
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::Critical) == 5);
    static_assert(uint32_t(HostBotPlanner::ScriptGoalPriority::Tactical) == 6);
    s_queued = 100;
    s_solved = 101;
    s_committed = 102;
    s_nativeCommits = 103;
    s_rejected = 104;
    s_unsupported = 105;
    s_budget = 106;
    s_unreachable = 107;
    s_stale = 108;
    s_gas = 109;
    s_pending = 110;
    s_gpuUs = 111;
    s_gpuFailures = 112;
    s_nodesCaptured = 113;
    s_roamSkipped = 114;
    s_roamQueued = 115;
    s_roamCandidates = 116;
    s_roamAccepted = 117;
    s_roamRejected = 118;
    s_roamFallbacks = 119;
    s_roamCancelled = 120;
    s_roamValidationTicks = 121;
    s_captureTicks = 122;
    HostBotPlanner::PlannerWork work{};
    SV_HostBotGpu_GetPlannerWork(nullptr);
    SV_HostBotGpu_GetPlannerWork(&work);
    uint64_t values[23]{};
    memcpy(values, &work, sizeof(work));
    for (unsigned i = 0; i < 23; ++i)
        Require(values[i] == 100 + i, "typed planner work getter exact23field layout");
    puts("PASS BR "
         "roam:200batch/coalescing/destination-not-hop/installedgoal/pathloss/rejection/profile/"
         "circle/cancel/NoEligible/fair200fallback/GPUoff/map");
    return 0;
}
