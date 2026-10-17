// Future approved-build fixture: compile the unchanged frozen production owner.
#include "DW_SlideView.cpp"

extern "C" { int _fltused = 0; }

namespace
{
    bool backend = true, mainThread = true, returnNull = false;
    dvar_t setting{};
    unsigned begins, ends, registrations, nativeCalls, completed;
    bool registrationValid;
    DWSlidePmove *seenPmove;
    const DWSlideGoalAngles *seenGoal;
    int32_t seenDuration, seenIn, seenOut, seenFlags;

    bool Same(const char *a, const char *b)
    {
        while (*a && *a == *b) { ++a; ++b; }
        return *a == *b;
    }
    bool Transition(DWSlidePmove *pmove, int32_t duration, int32_t in,
                    int32_t out, const DWSlideGoalAngles *goal, int32_t flags,
                    bool forwarded)
    {
        const auto before = nativeCalls;
        DW_SlideView_StartTransition(pmove, duration, in, out, goal, flags);
        ++completed;
        return nativeCalls == before + unsigned(forwarded) && (!forwarded ||
            (seenPmove == pmove && seenDuration == duration && seenIn == in &&
             seenOut == out && seenGoal == goal && seenFlags == flags));
    }
}

extern "C" bool DW_LocalBackend_IsEnabled() { return backend; }
extern "C" bool DSV_IsMainThread() { return mainThread; }
extern "C" void Dvar_BeginPermanentRegistration() { ++begins; }
extern "C" void Dvar_EndPermanentRegistration() { ++ends; }
extern "C" dvar_t *Dvar_RegisterBool(const char *name, bool value, uint32_t flags,
                                    const char *description)
{
    ++registrations;
    registrationValid = Same(name, "cg_useOldSlide") && !value && flags == 1 &&
        description && *description;
    setting.name = name;
    setting.flags = flags;
    setting.current.enabled = value;
    setting.reset.enabled = value;
    return returnNull ? nullptr : &setting;
}
extern "C" void DSV_OriginalStartTransition(DWSlidePmove *pmove, int32_t duration,
    int32_t in, int32_t out, const DWSlideGoalAngles *goal, int32_t flags)
{
    ++nativeCalls;
    seenPmove = pmove; seenDuration = duration; seenIn = in; seenOut = out;
    seenGoal = goal; seenFlags = flags;
}
// Freestanding fixture support for compiler-emitted aggregate initialization.
extern "C" void *memset(void *destination, int value, size_t count)
{
    auto *bytes = static_cast<volatile unsigned char *>(destination);
    for (size_t index = 0; index < count; ++index) bytes[index] = static_cast<unsigned char>(value);
    return destination;
}
extern "C" void *memcpy(void *destination, const void *source, size_t count)
{
    auto *out = static_cast<volatile unsigned char *>(destination);
    const auto *in = static_cast<const volatile unsigned char *>(source);
    for (size_t index = 0; index < count; ++index) out[index] = in[index];
    return destination;
}

#define CHECK(expression) do { if (!(expression)) return __LINE__; } while (false)
extern "C" __declspec(dllexport) int SlideView_Run()
{
    s_useOldSlide = nullptr;
    backend = mainThread = true; returnNull = false;
    setting = {}; begins = ends = registrations = nativeCalls = completed = 0;
    registrationValid = false;
    uint64_t state[80]{};
    DWSlidePmove pmove{nullptr, state};
    DWSlideGoalAngles goal{15.0f, 0.0f};
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true)); // uninitialized
    backend = false;
    DW_SlideView_Init(); CHECK(registrations == 0);
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    backend = true; mainThread = false;
    DW_SlideView_Init(); CHECK(registrations == 0);
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    mainThread = true; returnNull = true;
    DW_SlideView_Init(); CHECK(!s_useOldSlide && registrationValid);
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    returnNull = false; setting.type = 5;
    DW_SlideView_Init(); CHECK(!s_useOldSlide);
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    setting.type = 0;
    DW_SlideView_Init();
    CHECK(s_useOldSlide == &setting && registrationValid && begins == ends);
    const auto count = registrations;
    DW_SlideView_Init(); CHECK(registrations == count); // idempotent
    CHECK(!setting.current.enabled && !setting.reset.enabled && setting.flags == 1);
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, false)); // default 0 fixes
    setting.current.enabled = true;
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true)); // 1 restores native
    setting.current.enabled = false;
    constexpr int32_t flagCases[] = {0, 1, 2, 8, 10};
    for (const auto flags : flagCases)
        CHECK(Transition(&pmove, 1100, 4, 4, &goal, flags, true));
    constexpr int32_t durationCases[] = {0, 1099, 1101};
    for (const auto duration : durationCases)
        CHECK(Transition(&pmove, duration, 4, 4, &goal, 9, true));
    CHECK(Transition(&pmove, 1100, 3, 4, &goal, 9, true));
    CHECK(Transition(&pmove, 1100, 4, 3, &goal, 9, true));
    goal.pitch = 14.0f; CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    goal.pitch = 15.0f; goal.yaw = 1.0f;
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    goal.yaw = 0.0f;
    CHECK(Transition(nullptr, 1100, 4, 4, &goal, 9, true));
    pmove.playerState = nullptr;
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    pmove.playerState = state;
    CHECK(Transition(&pmove, 1100, 4, 4, nullptr, 9, true));
    backend = false;
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    backend = true; setting.type = 5;
    CHECK(Transition(&pmove, 1100, 4, 4, &goal, 9, true));
    for (auto value : state) CHECK(value == 0); // adapter never edits state
    return 0;
}
extern "C" __declspec(dllexport) unsigned SlideView_Cases() { return completed; }
