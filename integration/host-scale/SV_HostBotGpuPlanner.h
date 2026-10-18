#pragma once
#include "sv_host_navigation.h"

namespace HostBotPlanner
{
// Original Bot_GetGoalType table at Replay RVA45BF1F0, executed by the focused gate.
enum class ScriptGoalPriority : uint32_t
{
    None = 0,
    Hunt = 1,
    Guard = 2,
    Camp = 3,
    Objective = 4,
    Critical = 5,
    Tactical = 6
};
struct PlannerWork
{
    uint64_t queued, solved, committed, nativeCommits, rejected;
    uint64_t unsupported, searchBudget, unreachable, stale, gasRoutes;
    uint64_t pendingBatches, lastGpuMicroseconds, gpuFailures, capturedNodes;
    uint64_t roamCoalesced, roamQueued, roamCandidates, roamAccepted, roamRejected;
    uint64_t roamNativeFallbacks, roamCancelled, roamValidationTicks, captureTicks;
};
static_assert(sizeof(PlannerWork) == 184);
static_assert(offsetof(PlannerWork, roamCoalesced) == 112);
static_assert(offsetof(PlannerWork, roamValidationTicks) == 168);
static_assert(offsetof(PlannerWork, captureTicks) == 176);
enum class RouteState
{
    Fallback,
    Pending,
    Ready
};
void Frame(); // Frontend/main-thread initialization and dvar registration.
void BeginServerFrame(bool active);
void EndServerFrame();
bool Enabled();
bool Pending(unsigned slot);
void Cancel(unsigned slot);
RouteState Take(unsigned slot, const void *owner, const void *player, const void *navigator,
                uint64_t profile, const HostScale::NavAreaHandle &area,
                const HostScale::Vec3 &origin, HostScale::Vec3 &waypoint);
bool Queue(unsigned slot, const void *owner, const void *player, const void *navigator,
           uint64_t profile, const HostScale::NavAreaHandle &start,
           const HostScale::NavAreaHandle &goal, const HostScale::NavSearchSpec &spec,
           const HostScale::Vec3 &origin, const HostScale::Vec3 &destination);
// BR goal-generation owns a separate lifecycle; route Take/Pending never consume it.
RouteState RequestRoam(unsigned slot, const void *owner, const void *player, const void *navigator,
                       uint64_t profile, const HostScale::NavAreaHandle &area,
                       const HostScale::NavSearchSpec &spec, const HostScale::Vec3 &origin,
                       const HostScale::Vec3 &center, float radius, uint32_t gasGeneration,
                       uint32_t scriptType, const HostScale::Vec3 &scriptGoal, bool hasPath,
                       HostScale::Vec3 &destination);
bool RoamCandidateAllowed(const HostScale::Vec3 &origin, const HostScale::Vec3 &destination,
                          const HostScale::Vec3 &center, float insetRadius, bool newGoal = true);
bool RoamRepair(unsigned slot);
bool AdmitRoamValidation(unsigned slot);
void FinishRoam(unsigned slot, bool accepted, const HostScale::Vec3 *destination = nullptr);
void CancelRoam(unsigned slot);
void BindNativeRoamFallback(unsigned slot, const void *owner, const void *player,
                            const void *navigator, const void *scriptContext);
bool ConsumeNativeRoamFallback(unsigned slot, const void *player, const void *navigator,
                               const void *scriptContext);
void RecordRoamValidation(uint64_t ticks);
void RecordCommit(bool gpu, bool success, bool gas);
void PrintStatus();
} // namespace HostBotPlanner

extern "C" unsigned SV_HostBot_RequestRoamGoal(void *, const HostScale::Vec3 *, float,
                                               HostScale::Vec3 *, void *scriptContext = nullptr);
extern "C" void SV_HostBot_CancelRoamGoal(void *);

extern "C" void SV_HostBotGpu_GetPlannerWork(HostBotPlanner::PlannerWork *);
