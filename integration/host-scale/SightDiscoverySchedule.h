#pragma once
#include <stdint.h>

namespace HostScale
{
struct SightWorkCounters
{
    uint64_t urgentEvaluations, urgentNativeTraceDelta;
    uint64_t backgroundEvaluations, backgroundNativeTraceDelta;
    uint64_t backgroundDeferred, sharedCalls, admittedVisits;
    uint64_t urgentClockTicks, backgroundClockTicks;
};
static_assert(sizeof(SightWorkCounters) == 72);

// Scheduling state stores identity tokens and FIFO membership, never pointers
// that it dereferences or native visibility/geometry results.
class SightDiscoverySchedule
{
public:
    static constexpr unsigned Slots = 200;
    static constexpr unsigned PerVisit = 4;
    static constexpr unsigned VisitsPerFrame = 16;
    static constexpr unsigned FrameAllowance = PerVisit * VisitsPerFrame;
    static constexpr uint32_t RequestLeaseMilliseconds = 1000;

    struct Reservation
    {
        uint64_t epoch;
        uintptr_t entity, player, ai;
        unsigned slot, count;
    };

    template <class Eligible>
    Reservation Reserve(unsigned slot, unsigned slots, int32_t now, uintptr_t map,
                        uintptr_t entity, uintptr_t player, uintptr_t ai, Eligible eligible)
    {
        Reservation result{};
        if (slot >= slots || slots > Slots || !slots || !entity || !ai || !Lock())
            return result;
        if (!valid_ || map != map_ || now < now_ || slots != slots_)
            ResetLocked(map, now, slots);
        if (!frameValid_ || now != now_)
        {
            now_ = now;
            ++epoch_;
            frameValid_ = true;
            remaining_ = FrameAllowance;
            // The caller checks current live owners, never stored pointers.
            for (unsigned i = 0; i < pending_;)
            {
                const unsigned queued = queue_[i];
                const Slot &owner = state_[queued];
                // A valid owner can stop requesting work without leaving the roster.
                // Unsigned elapsed time is safe across the signed clock boundary;
                // backwards clocks reset the schedule before this loop.
                if (!eligible(queued, owner.entity, owner.player) ||
                    uint32_t(now) - uint32_t(owner.lastRequested) >= RequestLeaseMilliseconds)
                    Remove(i);
                else
                    ++i;
            }
            for (unsigned i = 0; i < Slots; ++i)
                admitted_[i] = false;
            const unsigned visits = pending_ < VisitsPerFrame ? pending_ : VisitsPerFrame;
            for (unsigned i = 0; i < visits; ++i)
                admitted_[queue_[i]] = true;
        }
        Slot &owner = state_[slot];
        if (owner.entity != entity || owner.player != player || owner.ai != ai)
        {
            RemoveSlot(slot);
            owner = {entity, player, ai, false, 0, now};
            admitted_[slot] = false;
        }
        owner.lastRequested = now;
        if (owner.servedEpoch == epoch_)
        {
            Unlock();
            return result;
        }
        if (!owner.queued)
        {
            queue_[pending_++] = slot;
            owner.queued = true;
        }
        unsigned position = 0;
        while (position < pending_ && queue_[position] != slot)
            ++position;
        // Sticky FIFO requests prevent first-called low slots or an unlucky
        // think/frame phase from repeatedly winning the shared allowance.
        if (admitted_[slot] && remaining_)
        {
            const unsigned count = remaining_ < PerVisit ? remaining_ : PerVisit;
            remaining_ -= count;
            owner.servedEpoch = epoch_;
            Remove(position);
            result = {epoch_, entity, player, ai, slot, count};
        }
        Unlock();
        return result;
    }

    void Finish(const Reservation &reservation, unsigned used)
    {
        if (!reservation.count || !Lock())
            return;
        if (reservation.epoch == epoch_ && reservation.slot < slots_)
        {
            const Slot &owner = state_[reservation.slot];
            if (owner.entity == reservation.entity && owner.player == reservation.player &&
                owner.ai == reservation.ai && used < reservation.count)
            {
                remaining_ += reservation.count - used;
                if (remaining_ > FrameAllowance)
                    remaining_ = FrameAllowance;
            }
        }
        Unlock();
    }

    void Reset()
    {
        if (!Lock())
            return;
        ResetLocked(0, 0, 0);
        valid_ = false;
        Unlock();
    }

private:
    struct Slot
    {
        uintptr_t entity, player, ai;
        bool queued;
        uint64_t servedEpoch;
        int32_t lastRequested;
    };
    Slot state_[Slots]{};
    unsigned queue_[Slots]{};
    bool admitted_[Slots]{};
    uintptr_t map_ = 0;
    uint64_t epoch_ = 0;
    int32_t now_ = 0;
    unsigned slots_ = 0, pending_ = 0, remaining_ = 0;
    bool valid_ = false, frameValid_ = false;
    uint8_t locked_ = 0;

    bool Lock() { return !__atomic_test_and_set(&locked_, __ATOMIC_ACQUIRE); }
    void Unlock() { __atomic_clear(&locked_, __ATOMIC_RELEASE); }
    void Remove(unsigned position)
    {
        state_[queue_[position]].queued = false;
        for (unsigned i = position + 1; i < pending_; ++i)
            queue_[i - 1] = queue_[i];
        --pending_;
    }
    void RemoveSlot(unsigned slot)
    {
        for (unsigned i = 0; i < pending_; ++i)
            if (queue_[i] == slot)
            {
                Remove(i);
                return;
            }
    }
    void ResetLocked(uintptr_t map, int32_t now, unsigned slots)
    {
        for (unsigned i = 0; i < Slots; ++i)
        {
            state_[i] = {};
            admitted_[i] = false;
        }
        map_ = map;
        now_ = now;
        slots_ = slots;
        pending_ = remaining_ = 0;
        valid_ = true;
        frameValid_ = false;
        ++epoch_;
    }
};
}

extern "C" void SV_HostSight_GetWork(HostScale::SightWorkCounters *out);
