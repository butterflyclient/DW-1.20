#include "DW_AltKillcamRenderBindings.h"

#include <intrin.h>

namespace
{
using namespace DWAltKillcamNative;

struct Stamp
{
    void *backend;
    ViewInfo *view;
    uint64_t token;
    DWAltKillcamViewport inset;
    uint32_t localClient;
    uint32_t nativeFrame;
    uint32_t viewIndex;
    uint32_t generation;
    DWAltKillcamBatch phase;
};

struct Capture
{
    SurfaceRecord *pool;
    const char *name;
    uint64_t token;
    uint64_t lastToken;
    uint32_t textureId;
    uint32_t format;
    uint32_t nativeFrame;
    uint32_t generation;
    DWAltKillcamViewport pixels;
    uint16_t handle;
    uint16_t width;
    uint16_t height;
};

constexpr const char *CaptureNames[2] = {"DW alt killcam capture 0", "DW alt killcam capture 1"};
constexpr float CaptureClear[4] = {0, 0, 0, 1};
volatile long StampLock;
Stamp Stamps[4]{};
Capture Captures[2]{};
bool Armed[2]{};
uint32_t Generations[2]{};
bool SessionUsed;

void Lock()
{
    while (_InterlockedCompareExchange(&StampLock, 1, 0))
        _mm_pause();
}

void Unlock()
{
    _InterlockedExchange(&StampLock, 0);
}

template <typename T> T &Field(void *base, unsigned offset)
{
    return *reinterpret_cast<T *>(static_cast<uint8_t *>(base) + offset);
}

SurfaceRecord *Surface(uint16_t handle)
{
    const unsigned index = (handle & 0x7fff);
    return AKR_SurfacePool && index && index <= 4096 ? AKR_SurfacePool + index - 1 : nullptr;
}

bool Owned(const Capture &capture)
{
    const auto *surface = Surface(capture.handle);
    return surface && capture.pool == AKR_SurfacePool && surface->imageName == capture.name &&
           surface->textureId == capture.textureId && surface->format == capture.format &&
           surface->width == capture.width && surface->height == capture.height &&
           (surface->internalFlags & 0x1003) == 0x1003;
}

void FinishGpu()
{
    // The native lock and submission owner protect the immediate queue. This
    // is needed only before release, never for the ordinary capture/draw pair.
    AKR_LockImmediate();
    const uint64_t fence = AKR_FlushImmediate();
    AKR_WaitFence(&fence, AKR_ImmediateQueue);
    AKR_UnlockImmediate();
}

void Release(Capture &capture)
{
    if (Owned(capture))
    {
        FinishGpu();
        AKR_DestroyPermanent(capture.handle);
    }
    capture = {};
}

bool TakeStamp(void *backend, const ViewInfo *view, Stamp &result, bool &armed)
{
    bool found = false;
    Lock();
    armed = Armed[view->localClient];
    for (auto &stamp : Stamps)
    {
        if (stamp.backend == backend)
        {
            result = stamp;
            stamp = {};
            found = result.localClient == view->localClient && result.view == view &&
                    result.nativeFrame == Field<uint32_t>(backend, 33256) &&
                    result.viewIndex == view->viewIndex && view->backend == backend &&
                    result.generation == Generations[view->localClient];
            break;
        }
    }
    Unlock();
    return found && armed;
}

bool EnsureCapture(Capture &capture, uint32_t localClient, const SurfaceRecord &source)
{
    if (Owned(capture) && capture.width == source.width && capture.height == source.height &&
        capture.format == source.format)
        return true;

    Release(capture);
    if (!source.width || !source.height || (source.internalFlags & 0x18))
        return false;

    uint16_t handle = 0;
    AKR_Create(&handle, source.width, source.height, source.width, source.height, 1, 1, 1,
               source.format, 2048, 3, CaptureClear, 192, CaptureNames[localClient], 0, nullptr, 0,
               nullptr);
    auto *surface = Surface(handle);
    if (!surface)
        return false;
    capture = {AKR_SurfacePool,
               CaptureNames[localClient],
               0,
               0,
               surface->textureId,
               surface->format,
               0,
               0,
               {},
               handle,
               surface->width,
               surface->height};
    return Owned(capture);
}

bool CaptureOutput(Context *context, uint16_t output, Capture &capture, uint32_t localClient,
                   uint64_t token, uint32_t nativeFrame)
{
    auto *source = Surface(output);
    if (!source || !EnsureCapture(capture, localClient, *source))
        return false;
    auto pixels = Field<DWAltKillcamViewport>(context->state, 4348);
    const int64_t right = int64_t(pixels.x) + pixels.width;
    const int64_t bottom = int64_t(pixels.y) + pixels.height;
    const int32_t x = pixels.x < 0 ? 0 : pixels.x;
    const int32_t y = pixels.y < 0 ? 0 : pixels.y;
    const int32_t endX = right > capture.width ? capture.width : int32_t(right);
    const int32_t endY = bottom > capture.height ? capture.height : int32_t(bottom);
    if (endX <= x || endY <= y)
        return false;
    pixels = {x, y, endX - x, endY - y};

    // Exact native Saved Scene copy contract. CopyTextureRegion reads the
    // currently bound color target; no display SRV or global target swap.
    AKR_Transition(context->state, capture.handle, -1, 192, 1024, 0);
    AKR_Transition(context->state, output, -1, 4, 2048, 0);
    AKR_FlushTransitions(context->state);
    AKR_CopyBoundColor(context, Surface(capture.handle)->Image(), 0, 0, 1, 1);
    AKR_Transition(context->state, capture.handle, -1, 1024, 192, 0);
    AKR_Transition(context->state, output, -1, 2048, 4, 0);
    AKR_FlushTransitions(context->state);
    capture.token = token;
    capture.lastToken = token;
    capture.nativeFrame = nativeFrame;
    capture.pixels = pixels;
    return true;
}

bool ValidInset(const DWAltKillcamViewport &inset, const DWAltKillcamViewport &display)
{
    return inset.width > 0 && inset.height > 0 && display.width > 0 && display.height > 0 &&
           inset.x >= display.x && inset.y >= display.y &&
           int64_t(inset.x) + inset.width <= int64_t(display.x) + display.width &&
           int64_t(inset.y) + inset.height <= int64_t(display.y) + display.height;
}

void Composite(Context *context, ViewInfo *view, const Stamp &stamp, Capture &capture)
{
    const bool retained = stamp.phase == DWAltKillcamBatch::RetainedKiller;
    const auto *output = Surface(Field<TargetGroup>(context->state, 4380).colors[0]);
    if (!Owned(capture) || capture.generation != stamp.generation || !output ||
        output->width != capture.width || output->height != capture.height ||
        output->format != capture.format ||
        (retained ? capture.lastToken != stamp.token
                  : (capture.token != stamp.token || capture.nativeFrame != stamp.nativeFrame)) ||
        !ValidInset(stamp.inset, view->displayViewport))
    {
        capture.token = 0;
        capture.lastToken = 0;
        return;
    }

    auto &source = *context->source;
    const auto viewport = source.viewport;
    const auto stateViewport = Field<DWAltKillcamViewport>(context->state, 4348);
    const auto scissor = Field<DWAltKillcamViewport>(context->state, 4364);
    void *const image = source.inputImage;
    source.inputImage = Surface(capture.handle)->Image();
    AKR_DrawRectangle(context, AKR_CopyMaterial, -1, &stamp.inset, 0, 0, float(stamp.inset.width),
                      float(stamp.inset.height), float(capture.pixels.x) / capture.width,
                      float(capture.pixels.y) / capture.height,
                      float(capture.pixels.x + capture.pixels.width) / capture.width,
                      float(capture.pixels.y + capture.pixels.height) / capture.height);
    source.inputImage = image;
    AKR_SetSourceViewport(context->source, &viewport);
    AKR_SetViewportScissor(context->state, &stateViewport, &scissor);
    capture.token = 0;
}
} // namespace

extern "C" bool DW_AltKillcamRender_SupportsCurrentGraph()
{
    return AKR_GraphScriptDvar && Field<int32_t>(AKR_GraphScriptDvar, 40) == 1;
}

extern "C" bool DW_AltKillcamRender_Stamp(void *backend, uint32_t localClient,
                                          DWAltKillcamBatch phase, uint64_t token,
                                          const DWAltKillcamViewport *inset)
{
    if (!backend || localClient >= 2 || !token || !inset ||
        (phase != DWAltKillcamBatch::Object && phase != DWAltKillcamBatch::Killer &&
         phase != DWAltKillcamBatch::RetainedKiller))
        return false;
    // The ordinary full graph owns the final display task. Native debug/HUD/
    // offscreen graph choices keep their stock path without an extra batch.
    if (!DW_AltKillcamRender_SupportsCurrentGraph())
        return false;
    const uint32_t index = Field<uint32_t>(backend, 33264);
    auto *views = Field<ViewInfo *>(backend, 33288);
    if (index >= 6 || !views)
        return false;
    Lock();
    Stamp *empty = nullptr;
    for (auto &stamp : Stamps)
    {
        if (stamp.backend == backend)
        {
            Unlock();
            return false;
        }
        if (!stamp.backend && !empty)
            empty = &stamp;
    }
    if (empty)
    {
        *empty = {backend,     views + index,
                  token,       *inset,
                  localClient, Field<uint32_t>(backend, 33256),
                  index,       Generations[localClient],
                  phase};
        Armed[localClient] = true;
        SessionUsed = true;
    }
    Unlock();
    return empty != nullptr;
}

extern "C" void DW_AltKillcamRender_Disarm(uint32_t localClient)
{
    if (localClient >= 2)
        return;
    Lock();
    Armed[localClient] = false;
    ++Generations[localClient];
    for (auto &stamp : Stamps)
        if (stamp.backend && stamp.localClient == localClient)
            stamp = {};
    Unlock();
}

extern "C" uint64_t DW_AltKillcamRender_FinalComposite(Context *context, const FinalTaskInfo *task,
                                                       ViewInfo *view, void *backend)
{
    const uint64_t nativeResult = AKR_FinalCompositeNative(context, task, view, backend);
    if (!context || !context->source || !context->state || !task || !view || view->localClient >= 2)
        return nativeResult;

    Stamp stamp{};
    bool armed = false;
    const bool stamped = TakeStamp(backend, view, stamp, armed);
    auto &capture = Captures[view->localClient];
    if (!armed)
    {
        Release(capture);
        return nativeResult;
    }
    if (!stamped || task->targets.count != 1 ||
        (task->targets.colors[0] & 0x7fff) !=
            (Field<TargetGroup>(context->state, 4380).colors[0] & 0x7fff))
    {
        capture.token = 0;
        capture.lastToken = 0;
        return nativeResult;
    }
    if (stamp.phase == DWAltKillcamBatch::Object)
    {
        capture.token = 0;
        capture.lastToken = 0;
        if (CaptureOutput(context, task->targets.colors[0], capture, view->localClient, stamp.token,
                          stamp.nativeFrame))
            capture.generation = stamp.generation;
    }
    else
        Composite(context, view, stamp, capture);
    return nativeResult;
}

extern "C" uint64_t DW_AltKillcamRender_DestroyGlobalTargets()
{
    Lock();
    const bool used = SessionUsed;
    Unlock();
    if (!used)
        return AKR_DestroyGlobalTargetsNative();
    // Stock caller has completed render submission before destroying global
    // targets. Drain GPU references before releasing our permanent RTs too.
    AKR_SyncRenderThread();
    for (auto &capture : Captures)
        Release(capture);
    Lock();
    for (auto &stamp : Stamps)
        stamp = {};
    Armed[0] = Armed[1] = false;
    SessionUsed = false;
    Unlock();
    return AKR_DestroyGlobalTargetsNative();
}
