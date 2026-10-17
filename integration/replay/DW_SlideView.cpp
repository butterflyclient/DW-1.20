#include "DW_SlideView.h"
#include "DW_SlideViewBindings.h"
#include "replay_dvar.h"

extern "C" bool DW_LocalBackend_IsEnabled();

namespace
{
    dvar_t *s_useOldSlide;

    bool FixEnabled()
    {
        const auto *setting = __atomic_load_n(&s_useOldSlide, __ATOMIC_ACQUIRE);
        return setting && setting->type == 0 && !setting->current.enabled;
    }

    bool IsSlidePitchTransition(const DWSlidePmove *pmove, int32_t duration,
        int32_t easeIn, int32_t easeOut, const DWSlideGoalAngles *goal, int32_t flags)
    {
        // These are the complete arguments at Replay Slide_Update's only call
        // to PM_StartViewAngleTransition. The other native callers use flags 1
        // (center view) and 2 (mantle yaw), so they always retain native behavior.
        return pmove && pmove->playerState && goal && flags == 9 &&
            duration == 1100 && easeIn == 4 && easeOut == 4 &&
            goal->pitch == 15.0f && goal->yaw == 0.0f;
    }
}

extern "C" void DW_SlideView_Init()
{
    if (__atomic_load_n(&s_useOldSlide, __ATOMIC_ACQUIRE) ||
        !DW_LocalBackend_IsEnabled() || !DSV_IsMainThread())
        return;
    Dvar_BeginPermanentRegistration();
    auto *setting = Dvar_RegisterBool("cg_useOldSlide", false, 1,
        "Use original forced slide pitch. Match this setting on client and server.");
    Dvar_EndPermanentRegistration();
    if (setting && setting->type == 0)
        __atomic_store_n(&s_useOldSlide, setting, __ATOMIC_RELEASE);
}

extern "C" void DW_SlideView_StartTransition(DWSlidePmove *pmove, int32_t duration,
    int32_t easeIn, int32_t easeOut, const DWSlideGoalAngles *goal, int32_t flags)
{
    // Prevent the native forced slide-pitch transition from being created.
    // Slide movement, events, gestures, sprint accounting and jump state still
    // execute in the original Slide_Update caller. No angle is rewritten here.
    if (DW_LocalBackend_IsEnabled() && FixEnabled() &&
        IsSlidePitchTransition(pmove, duration, easeIn, easeOut, goal, flags))
        return;
    DSV_OriginalStartTransition(pmove, duration, easeIn, easeOut, goal, flags);
}
