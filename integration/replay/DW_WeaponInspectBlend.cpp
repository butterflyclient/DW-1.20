#include "DW_WeaponInspectBlend.h"
#include "DW_WeaponInspectBlendBindings.h"

extern "C" bool DW_LocalBackend_IsEnabled();

namespace
{
    constexpr int32_t ScriptedAnimation = 70;
    constexpr uint32_t ScriptedNode = 380;

    float InspectTransition(int32_t animation, uint32_t animationIndex,
                            int32_t previousAnimation, uint32_t previousAnimationIndex)
    {
        // Native tree initialization sets cached weapAnim=-1. The animation
        // caller clears its toggle bit, producing -129 with default node236.
        // That first entry has an initialized idle pose available to blend.
        const bool initializedIdle = previousAnimation == -129 && previousAnimationIndex == 236;
        if (animation == ScriptedAnimation && animationIndex == ScriptedNode &&
            (previousAnimation == 0 || previousAnimation == 1 || initializedIdle))
            return 0.1f;
        if (previousAnimation != ScriptedAnimation || previousAnimationIndex != ScriptedNode)
            return 0.0f;
        // The later build inserted a reload enum at22 and uses scripted71.
        // These are the target Replay enums, translated through both native
        // BG_MapWeaponAnimStateToAnimIndex functions by the preparer's proof.
        switch (animation)
        {
        case 16: case 17: case 18: case 19: case 20: case 13:
        case 22: case 24: case 25: case 27: case 61: case 70:
            return 0.2f;
        case 0: case 1: case 2: case 3: case 28:
        case 10: case 11: case 12: case 71:
            return 0.1f;
        default:
            return 0.0f;
        }
    }
}

extern "C" uint64_t DW_WeaponInspectBlend_StartWeaponAnim(int32_t local, const void *weapon,
    int32_t hand, int32_t animation, uint32_t animationIndex,
    int32_t previousAnimation, uint32_t previousAnimationIndex,
    float transitionTime, uint8_t forceTransitionTime)
{
    if (DW_LocalBackend_IsEnabled() && !forceTransitionTime &&
        WIB_ViewmodelAnimBlending && local >= 0 && local < 2 && hand == 0)
    {
        const auto *globals = WIB_ClientGlobals[local];
        const auto *ps = globals ? reinterpret_cast<const DWInspectPlayerState *>(globals + 8) : nullptr;
        if (ps && DW_WeaponInspect_HasClip(ps))
        {
            const float duration = InspectTransition(animation, animationIndex,
                previousAnimation, previousAnimationIndex);
            if (duration > 0.0f)
                transitionTime = duration;
        }
    }
    // The complete original owner computes native rates and LINEAR weights,
    // preserves animation time/notifies, and handles all other animation work.
    return WIB_OriginalStartWeaponAnim(local, weapon, hand, animation, animationIndex,
        previousAnimation, previousAnimationIndex, transitionTime, forceTransitionTime);
}
