#include "SightDiscoverySchedule.h"
#include <stddef.h>

static HostScale::SightDiscoverySchedule schedule;
static unsigned char disabled[200];
static HostScale::SightDiscoverySchedule::Reservation reservations[200];
extern "C" void *memset(void *destination, int value, size_t length)
{
    volatile unsigned char *out = static_cast<volatile unsigned char *>(destination);
    for (size_t i = 0; i < length; ++i)
        out[i] = static_cast<unsigned char>(value);
    return destination;
}
extern "C" __declspec(dllexport) void Reset() { schedule.Reset(); }
extern "C" __declspec(dllexport) unsigned Reserve(unsigned slot, unsigned slots, int now,
                                                 uintptr_t map, uintptr_t identity)
{
    if (slot >= 200)
        return 0;
    reservations[slot] = schedule.Reserve(slot, slots, now, map, identity, identity + 1, identity + 2,
        [](unsigned candidate, uintptr_t, uintptr_t) { return !disabled[candidate]; });
    return reservations[slot].count;
}
extern "C" __declspec(dllexport) void Finish(unsigned slot, unsigned used)
{
    if (slot < 200)
        schedule.Finish(reservations[slot], used);
}

extern "C" __declspec(dllexport) void Disable(unsigned slot, unsigned value)
{
    if (slot < 200) disabled[slot] = value != 0;
}
