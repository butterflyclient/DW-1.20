#ifndef DW_SLIDE_HEADER
#define DW_SLIDE_HEADER "../integration/host-scale/sv_host_bot_slide.h"
#endif
#include DW_SLIDE_HEADER
#include <assert.h>
#include <stdio.h>

using namespace HostScale::SlideCancel;

int main()
{
    State state{};
    Reset(state, 42, 0);
    assert(state.nextAttempt >= 2500 && state.nextAttempt <= 7000);
    const int32_t start = int32_t(state.nextAttempt);
    assert(Update(state, start - 1, Sprinting, true, true).buttons == 0);
    assert(Update(state, start, 0, true, true).buttons == 0); // Actual sprint required.
    assert(Update(state, start, Sprinting | Sliding, true, true).buttons == 0);
    assert(Update(state, start, Sprinting, true, false).buttons == 0);
    auto decision = Update(state, start, Sprinting, true, true);
    assert(decision.active && decision.buttons == SlideRequest);
    assert(state.nextAttempt >= start + 8000 && state.nextAttempt <= start + 15000);
    decision = Update(state, start + 50, Sprinting | Sliding, true, false);
    assert(decision.active && !decision.buttons);
    const int32_t cancel = int32_t(state.cancelTime);
    assert(cancel >= start + 210 && cancel <= start + 370);
    decision = Update(state, cancel - 1, Sliding, true, false);
    assert(decision.active && !decision.buttons);
    decision = Update(state, cancel, Sliding, true, false);
    assert(decision.active && decision.buttons == CrouchRequest);
    decision = Update(state, cancel + 50, Crouched, true, false);
    assert(decision.active && !decision.buttons); // Space from crouch releases C.
    decision = Update(state, cancel + 100, 0, true, false);
    assert(!decision.active && !decision.buttons && state.phase == Phase::Idle);
    assert(!Update(state, cancel + 150, Sprinting, true, true).active);

    Reset(state, 42, 0);
    const int32_t rejected = int32_t(state.nextAttempt);
    assert(Update(state, rejected, Sprinting, true, true).buttons == SlideRequest);
    assert(!Update(state, rejected + 1000, Sprinting, true, true).active);
    assert(state.phase == Phase::Idle); // Native rejected slide: no blind C/jump.

    const Phase phases[] = {Phase::AwaitSlide, Phase::Sliding, Phase::AwaitCrouch, Phase::AwaitStand};
    for (const auto phase : phases)
    {
        Reset(state, 42, 0);
        state.phase = phase;
        state.deadline = 1000;
        decision = Update(state, 100, Sliding | Crouched, false, false);
        assert(!decision.active && !decision.buttons && state.phase == Phase::Idle);
    }

    Reset(state, 42, 0);
    state.phase = Phase::Sliding;
    state.deadline = 1000;
    decision = Update(state, 100, 0, true, false);
    assert(!decision.active && !decision.buttons); // Naturally ended: leave stance native.
    state.phase = Phase::AwaitStand;
    state.deadline = 400;
    assert(Update(state, 399, Crouched, true, false).active);
    assert(!Update(state, 400, Crouched, true, false).active); // Blocked clearance times out.

    unsigned different = 0;
    int64_t previous = -1;
    for (uint64_t profile = 1; profile <= 200; ++profile)
    {
        Reset(state, profile, 0);
        different += state.nextAttempt != previous;
        previous = state.nextAttempt;
        const int32_t time = int32_t(state.nextAttempt);
        for (unsigned frame = 0; frame < 20; ++frame)
        {
            const auto flags = frame < 2 ? Sprinting : frame < 10 ? Sliding : Crouched;
            decision = Update(state, time + int32_t(frame * 50), flags, true, true);
            assert(!(decision.buttons & (uint64_t{0x100} | 0x40))); // No jump or prone.
        }
    }
    assert(different > 190); // Roster profiles do not synchronize their first attempt.
    Reset(state, 0x534c49444543414eull, 0);
    assert(state.random); // The XOR seed's zero case is safe.
    puts("PASS: native C-slide/C-cancel/Space-stand edges, cooldown, interruption and rejection");
}
