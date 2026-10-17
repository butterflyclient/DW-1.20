#pragma once
#include <stdint.h>
#include <stddef.h>

// Only the native arguments consumed by this adapter are reconstructed. The
// original transition function owns all playerState storage and angle packing.
struct DWSlidePmove
{
    void *vtable;
    void *playerState;
};
static_assert(sizeof(DWSlidePmove) == 16);
static_assert(offsetof(DWSlidePmove, playerState) == 8);

struct DWSlideGoalAngles
{
    float pitch;
    float yaw;
};
static_assert(sizeof(DWSlideGoalAngles) == 8);
static_assert(offsetof(DWSlideGoalAngles, yaw) == 4);

extern "C" {
void DW_SlideView_Init();
void DW_SlideView_StartTransition(DWSlidePmove *pmove, int32_t duration,
    int32_t easeIn, int32_t easeOut, const DWSlideGoalAngles *goal, int32_t flags);
}
