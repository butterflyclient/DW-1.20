#pragma once
#include "DW_WeaponInspect.h"

extern "C" {
// Retained type16 clip identity, independent of the playing flag/state. The
// runtime owns this lookup so an exit can still identify its outgoing clip.
bool DW_WeaponInspect_HasClip(const DWInspectPlayerState *ps);
uint64_t DW_WeaponInspectBlend_StartWeaponAnim(int32_t local, const void *weapon,
    int32_t hand, int32_t animation, uint32_t animationIndex,
    int32_t previousAnimation, uint32_t previousAnimationIndex,
    float transitionTime, uint8_t forceTransitionTime);
}
