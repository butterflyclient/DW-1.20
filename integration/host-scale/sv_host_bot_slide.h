#pragma once
#include <stdint.h>

namespace HostScale::SlideCancel
{
    // Replay 1.20 native slide/stance consumers own all movement and timers.
    constexpr uint64_t SlideRequest = 0x400000;
    constexpr uint64_t CrouchRequest = 0x80;
    constexpr uint64_t Sliding = uint64_t{1} << 29;
    constexpr uint64_t Crouched = uint64_t{1} << 1;
    constexpr uint64_t Sprinting = uint64_t{1} << 20;

    enum class Phase : uint8_t { Idle, AwaitSlide, Sliding, AwaitCrouch, AwaitStand };
    struct State
    {
        uint64_t random;
        int64_t nextAttempt, deadline, cancelTime;
        Phase phase;
    };
    struct Decision { uint64_t buttons; bool active; };

    inline unsigned Random(State &state, unsigned range)
    {
        // Independent per-roster randomness leaves native brain RNG untouched.
        uint64_t value = state.random;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        state.random = value;
        return unsigned((value * 0x2545f4914f6cdd1dull) % range);
    }

    inline void Reset(State &state, uint64_t profile, int32_t now)
    {
        state = {};
        state.random = profile ^ 0x534c49444543414eull;
        if (!state.random)
            state.random = 1;
        state.nextAttempt = int64_t(now) + 2500 + Random(state, 4501);
    }

    inline Decision Update(State &state, int32_t now, uint64_t flags, bool safe, bool canStart)
    {
        if (!safe || (state.phase != Phase::Idle && int64_t(now) >= state.deadline))
        {
            state.phase = Phase::Idle;
            return {};
        }
        switch (state.phase)
        {
        case Phase::Idle:
            if (!canStart || (flags & Sliding) || !(flags & Sprinting) || now < state.nextAttempt)
                return {};
            state.nextAttempt = int64_t(now) + 8000 + Random(state, 7001);
            state.deadline = int64_t(now) + 1000;
            state.phase = Phase::AwaitSlide;
            // C while sprinting selects native slide stance, which sends its
            // request without holding the crouch bit. Physics may reject it.
            return {SlideRequest, true};
        case Phase::AwaitSlide:
            if (flags & Sliding)
            {
                state.cancelTime = int64_t(now) + 160 + Random(state, 161);
                state.phase = Phase::Sliding;
            }
            return {0, true};
        case Phase::Sliding:
            if (!(flags & Sliding))
            {
                state.phase = Phase::Idle;
                return {};
            }
            if (now < state.cancelTime)
                return {0, true};
            state.deadline = int64_t(now) + 400;
            state.phase = Phase::AwaitCrouch;
            // The fresh second C edge ends the acknowledged native slide.
            return {CrouchRequest, true};
        case Phase::AwaitCrouch:
            if (flags & Sliding)
                return {CrouchRequest, true};
            if (!(flags & Crouched))
            {
                state.phase = Phase::Idle;
                return {};
            }
            state.deadline = int64_t(now) + 400;
            state.phase = Phase::AwaitStand;
            // Space from crouch selects stand before the client emits a jump.
            // The resulting usercmd releases crouch; no jump/prone is authored.
            return {0, true};
        case Phase::AwaitStand:
            if (!(flags & Crouched))
            {
                state.phase = Phase::Idle;
                return {};
            }
            return {0, true};
        }
        return {};
    }
}
