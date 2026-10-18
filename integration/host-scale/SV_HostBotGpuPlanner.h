#pragma once
#include "sv_host_navigation.h"

namespace HostBotPlanner
{
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
void RecordCommit(bool gpu, bool success, bool gas);
void PrintStatus();
} // namespace HostBotPlanner
