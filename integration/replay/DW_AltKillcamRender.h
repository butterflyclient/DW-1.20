#pragma once

#include <stdint.h>

// These are display pixels in the native main view, including its origin.
struct DWAltKillcamViewport
{
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};
static_assert(sizeof(DWAltKillcamViewport) == 16);

enum class DWAltKillcamBatch : uint32_t
{
    Object = 1,
    Killer = 2,
    RetainedKiller = 3,
};

extern "C"
{
    // Check before changing the native camera or prediction owner.
    // This reads the current graph choice without allocating or changing RTs.
    bool DW_AltKillcamRender_SupportsCurrentGraph();
    // Stamp after BeginFrame and GetNextViewInfoIndex, before RenderScene.
    // Object and killer batches share one nonzero token, never reused next frame.
    // A rejected stamp must leave that batch on its ordinary rendering path.
    // RetainedKiller uses the last successful object token for this killcam;
    // it submits only the ordinary main scene and never reads capture state.
    bool DW_AltKillcamRender_Stamp(void *backendData, uint32_t localClient, DWAltKillcamBatch phase,
                                   uint64_t token, const DWAltKillcamViewport *inset);
    void DW_AltKillcamRender_Disarm(uint32_t localClient);
}
