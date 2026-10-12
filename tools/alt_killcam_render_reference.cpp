#include "DW_AltKillcamRenderBindings.h"

using namespace DWAltKillcamNative;

// Complete original final-task behavior. The pinned native body carries an
// undecoded handler family, so this body is compiled with fresh native unwind
// instead of retaining code while discarding its original handler metadata.
extern "C" uint64_t AKR_FinalCompositeNative(Context *context, const FinalTaskInfo *task,
                                             ViewInfo *view, void *backend)
{
    const uint16_t scene = task->attachments[0];
    const uint16_t auxiliary = task->attachments[1];
    const uint16_t depth[2] = {task->attachments[2], task->attachments[3]};
    const bool pairedDepth = depth[0] && depth[1];
    const uint16_t overlay = task->attachments[4];
    const uint16_t film = task->attachments[5];
    const auto *source = AKR_SurfacePool + (scene & 0x7fff) - 1;
    const auto *target = AKR_SurfacePool + (task->targets.colors[0] & 0x7fff) - 1;
    const float inverseScale = 1.0f / AKR_ResolutionScale();
    DWAltKillcamViewport viewport{};
    viewport.width = int32_t(float(source->width) * inverseScale);
    viewport.height = int32_t(float(source->height) * inverseScale);
    const int widthGap = int(target->width) - viewport.width;
    const int heightGap = int(target->height) - viewport.height;
    viewport.x = (widthGap < 0 ? 0 : widthGap) / 2;
    viewport.y = (heightGap < 0 ? 0 : heightGap) / 2;
    if (viewport.x || viewport.y)
        AKR_ClearTargets(context->state, 15, 0);
    Context copy = *context;
    AKR_PostfxConstants(&copy, view, backend, true, pairedDepth, overlay != 0, film != 0);
    copy = *context;
    return AKR_PostfxApply(&copy, view, &viewport, scene, auxiliary, depth, overlay, film);
}
