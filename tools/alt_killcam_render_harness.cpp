#include "DW_AltKillcamRenderBindings.h"
#include <string.h>

using namespace DWAltKillcamNative;
extern "C" uint64_t DW_AltKillcamRender_FinalComposite(Context *, const FinalTaskInfo *, ViewInfo *,
                                                       void *);
extern "C" uint64_t DW_AltKillcamRender_DestroyGlobalTargets();

namespace
{
SurfaceRecord Pool[4096]{};
SourceState Source{};
uint8_t State[4400]{};
ViewInfo View{};
FinalTaskInfo Task{};
uint8_t Backend[2][33400]{};
uint32_t Pixels[4096]{};
uint32_t Original, Copies, Draws, Destroys, Submits, Waits, Resets, Locks, Syncs;
uint32_t Paint, Drawn;
unsigned Error;
unsigned BadIdentity;
float ResolutionScale = 1;
int32_t FallbackResults[16]{};
DWAltKillcamViewport ExpectedInset{1440, 810, 480, 270};
float ExpectedUv[4] = {0, 0, 1, 1};
Context Ctx{&Source, State};

TargetGroup &Group()
{
    return *reinterpret_cast<TargetGroup *>(State + 4380);
}
DWAltKillcamViewport &StateViewport()
{
    return *reinterpret_cast<DWAltKillcamViewport *>(State + 4348);
}
DWAltKillcamViewport &Scissor()
{
    return *reinterpret_cast<DWAltKillcamViewport *>(State + 4364);
}
bool StampFrame(unsigned phase, uint64_t token, const DWAltKillcamViewport *inset = nullptr)
{
    return DW_AltKillcamRender_Stamp(Backend[phase & 1], View.localClient,
                                     static_cast<DWAltKillcamBatch>(phase), token,
                                     inset ? inset : &ExpectedInset);
}
void Frame(unsigned phase, uint32_t paint)
{
    Paint = paint;
    const auto result = DW_AltKillcamRender_FinalComposite(&Ctx, &Task, &View, Backend[phase & 1]);
    if (result != uint64_t(paint) * 0x100000001)
        Error |= 64;
}
} // namespace

extern "C"
{
    SurfaceRecord *AKR_SurfacePool = Pool;
    int32_t GraphScriptDvar[11]{};
    void *AKR_GraphScriptDvar = GraphScriptDvar;
    uint8_t AKR_ImmediateQueue[1096]{};
    void *AKR_CopyMaterial = reinterpret_cast<void *>(0x1234);
    uint16_t *AKR_Create(uint16_t *out, int32_t width, uint32_t height, uint32_t allocWidth,
                         uint32_t allocHeight, uint32_t depth, uint32_t arrays, uint32_t mips,
                         uint32_t format, uint32_t flags, uint32_t internal, const float *clear,
                         uint32_t resourceState, const char *name, uint16_t tiling, void *placement,
                         uint64_t offset, void *display)
    {
        if (allocWidth != unsigned(width) || allocHeight != height || depth != 1 || arrays != 1 ||
            mips != 1 || flags != 2048 || internal != 3 || clear[3] != 1 || resourceState != 192 ||
            tiling || placement || offset || display)
            Error |= 1;
        for (unsigned index = 1; index < 4096; ++index)
            if (!Pool[index].internalFlags)
            {
                Pool[index].internalFlags = 0x1003;
                Pool[index].imageName = name;
                Pool[index].textureId = 100 + index;
                Pool[index].format = format;
                Pool[index].width = uint16_t(width);
                Pool[index].height = uint16_t(height);
                *out = uint16_t(index + 1);
                return out;
            }
        *out = 0;
        return out;
    }
    void AKR_Transition(void *, uint16_t, int32_t subresource, uint32_t before, uint32_t after,
                        uint32_t flags)
    {
        if (subresource != -1 || flags ||
            !((before == 192 && after == 1024) || (before == 1024 && after == 192) ||
              (before == 4 && after == 2048) || (before == 2048 && after == 4)))
            Error |= 2;
    }
    void AKR_FlushTransitions(void *)
    {
    }
    void AKR_CopyBoundColor(Context *context, void *image, float x, float y, float w, float h)
    {
        ++Copies;
        auto *surface = reinterpret_cast<SurfaceRecord *>(static_cast<uint8_t *>(image) - 24);
        if (context != &Ctx || x || y || w != 1 || h != 1)
            Error |= 4;
        Pixels[surface - Pool] = Pixels[(Group().colors[0] & 0x7fff) - 1];
    }
    void AKR_DrawRectangle(Context *context, void *material, int32_t color,
                           const DWAltKillcamViewport *viewport, float x, float y, float w, float h,
                           float s0, float t0, float s1, float t1)
    {
        ++Draws;
        if (context != &Ctx || material != AKR_CopyMaterial || color != -1 || x || y ||
            w != viewport->width || h != viewport->height || s0 != ExpectedUv[0] ||
            t0 != ExpectedUv[1] || s1 != ExpectedUv[2] || t1 != ExpectedUv[3] ||
            memcmp(viewport, &ExpectedInset, 16))
            Error |= 8;
        auto *surface = reinterpret_cast<SurfaceRecord *>(
            static_cast<uint8_t *>(context->source->inputImage) - 24);
        Drawn = Pixels[surface - Pool];
        StateViewport() = Scissor() = *viewport;
        Source.viewport = *viewport;
    }
    void AKR_SetSourceViewport(SourceState *source, const DWAltKillcamViewport *viewport)
    {
        source->viewport = *viewport;
    }
    void AKR_SetViewportScissor(void *, const DWAltKillcamViewport *viewport,
                                const DWAltKillcamViewport *scissor)
    {
        StateViewport() = *viewport;
        Scissor() = *scissor;
    }
    void AKR_DestroyPermanent(uint16_t handle)
    {
        ++Destroys;
        if (Waits != Submits || Locks || !Waits)
            Error |= 16;
        Pool[(handle & 0x7fff) - 1] = {};
    }
    void AKR_LockImmediate()
    {
        ++Locks;
    }
    void AKR_UnlockImmediate()
    {
        --Locks;
    }
    uint64_t AKR_FlushImmediate()
    {
        ++Submits;
        return 77;
    }
    void AKR_WaitFence(const uint64_t *fence, void *queue)
    {
        ++Waits;
        if (*fence != 77 || queue != AKR_ImmediateQueue || !Locks)
            Error |= 32;
    }
    void AKR_SyncRenderThread()
    {
        ++Syncs;
    }
#ifndef DW_ALT_KILLCAM_FALLBACK_TEST
    uint64_t AKR_FinalCompositeNative(Context *, const FinalTaskInfo *, ViewInfo *, void *backend)
    {
        ++Original;
        Group() = Task.targets;
        StateViewport() = Scissor() = Source.viewport = View.displayViewport;
        Pixels[0] = Paint;
        View.backend = BadIdentity == 1 ? nullptr : backend;
        View.viewIndex = BadIdentity == 2 ? 1 : 0;
        return uint64_t(Paint) * 0x100000001;
    }
#endif
    float AKR_ResolutionScale()
    {
        return ResolutionScale;
    }
    void AKR_ClearTargets(void *, uint8_t flags, uint8_t stencil)
    {
        FallbackResults[0] = flags;
        FallbackResults[1] = stencil;
    }
    void AKR_PostfxConstants(Context *, ViewInfo *, void *, bool display, bool pairedDepth,
                             bool overlay, bool film)
    {
        FallbackResults[2] = display;
        FallbackResults[3] = pairedDepth;
        FallbackResults[4] = overlay;
        FallbackResults[5] = film;
    }
    uint64_t AKR_PostfxApply(Context *, ViewInfo *, const DWAltKillcamViewport *viewport,
                             uint16_t scene, uint16_t auxiliary, const uint16_t *depth,
                             uint16_t overlay, uint16_t film)
    {
        memcpy(FallbackResults + 6, viewport, 16);
        FallbackResults[10] = scene;
        FallbackResults[11] = auxiliary;
        FallbackResults[12] = depth[0];
        FallbackResults[13] = depth[1];
        FallbackResults[14] = overlay;
        FallbackResults[15] = film;
        return 0;
    }
    uint64_t AKR_DestroyGlobalTargetsNative()
    {
        ++Resets;
        memset(Pool, 0, sizeof(Pool));
        return 0x123456;
    }

    __declspec(dllexport) unsigned Test_Case(unsigned scenario)
    {
        GraphScriptDvar[10] = 1;
        DW_AltKillcamRender_DestroyGlobalTargets();
        Original = Copies = Draws = Destroys = Submits = Waits = Resets = Locks = Syncs = Error =
            BadIdentity = 0;
        for (auto &data : Backend)
        {
            *reinterpret_cast<uint32_t *>(data + 33256) = 1;
            *reinterpret_cast<uint32_t *>(data + 33264) = 0;
            *reinterpret_cast<ViewInfo **>(data + 33288) = &View;
        }
        View.localClient = 0;
        View.displayViewport = {0, 0, 1920, 1080};
        ExpectedInset = {1440, 810, 480, 270};
        ExpectedUv[0] = ExpectedUv[1] = 0;
        ExpectedUv[2] = ExpectedUv[3] = 1;
        if (scenario == 18)
        {
            View.displayViewport = {960, 0, 960, 1080};
            ExpectedUv[0] = 0.5f;
        }
        if (scenario == 19)
        {
            View.displayViewport = {0, 0, 960, 1080};
            ExpectedInset.x = 480;
            ExpectedUv[2] = 0.5f;
        }
        Source.inputImage = reinterpret_cast<void *>(0x4567);
        Pool[0].internalFlags = 0x1043;
        Pool[0].format = 28;
        Pool[0].width = 1920;
        Pool[0].height = 1080;
        Task.targets = {1, 0, {1, 0, 0, 0}, 0, 0};
        if (scenario == 20)
        {
            if (!DW_AltKillcamRender_SupportsCurrentGraph())
                return 1;
            GraphScriptDvar[10] = 4;
            if (DW_AltKillcamRender_SupportsCurrentGraph() || StampFrame(1, 17))
                return 2;
            AKR_GraphScriptDvar = nullptr;
            const bool unavailable = DW_AltKillcamRender_SupportsCurrentGraph();
            AKR_GraphScriptDvar = GraphScriptDvar;
            return unavailable || Copies || Draws || Destroys || Submits || Syncs ? 4 : 0;
        }
        if (scenario == 0)
        {
            Frame(2, 22);
            return Error | (Original != 1 || Copies || Draws ? 256 : 0);
        }
        if (scenario == 15)
        {
            const auto result = DW_AltKillcamRender_DestroyGlobalTargets();
            return Error | (result != 0x123456 || Syncs || Submits || Destroys ? 256 : 0);
        }
        if (scenario == 5)
        {
            if (!StampFrame(1, 17))
                return 512;
            DW_AltKillcamRender_Disarm(0);
            Frame(1, 11);
            return Error | (Copies || Draws ? 256 : 0);
        }
        if (scenario == 9)
        {
            uint8_t keys[5][33400]{};
            for (unsigned index = 0; index < 4; ++index)
            {
                *reinterpret_cast<ViewInfo **>(keys[index] + 33288) = &View;
                if (!DW_AltKillcamRender_Stamp(keys[index], 0, DWAltKillcamBatch::Object, index + 1,
                                               &ExpectedInset))
                    return 512;
            }
            *reinterpret_cast<ViewInfo **>(keys[4] + 33288) = &View;
            bool overflow =
                DW_AltKillcamRender_Stamp(keys[4], 0, DWAltKillcamBatch::Object, 5, &ExpectedInset);
            DW_AltKillcamRender_Disarm(0);
            return overflow ? 256 : 0;
        }
        if (scenario == 10)
            return (DW_AltKillcamRender_Stamp(nullptr, 0, DWAltKillcamBatch::Object, 1,
                                              &ExpectedInset) ||
                    DW_AltKillcamRender_Stamp(Backend[0], 2, DWAltKillcamBatch::Object, 1,
                                              &ExpectedInset) ||
                    StampFrame(1, 0))
                       ? 256
                       : 0;
        if (!StampFrame(1, 17))
            return 512;
        if (scenario >= 11 && scenario <= 13)
        {
            if (scenario == 11)
                *reinterpret_cast<uint32_t *>(Backend[1] + 33256) = 2;
            else
                BadIdentity = scenario == 12 ? 1 : 2;
            Frame(1, 11);
            DW_AltKillcamRender_Disarm(0);
            return Error | (Copies || Draws ? 256 : 0);
        }
        if (scenario == 4 && StampFrame(1, 18))
            return 256;
        Frame(1, 11);
        if (Copies != 1)
            return 1024;
        if (scenario >= 21 && scenario <= 28)
        {
            if (!StampFrame(2, 17))
                return 512;
            Frame(2, 22);
            if (Draws != 1)
                return 1024;
            *reinterpret_cast<uint32_t *>(Backend[1] + 33256) = 7;
            unsigned expected = 2;
            uint64_t retainedToken = 17;
            if (scenario == 22)
            {
                DW_AltKillcamRender_Disarm(0);
                expected = 1;
            }
            else if (scenario == 23)
            {
                retainedToken = 99;
                expected = 1;
            }
            else if (scenario == 24)
            {
                Pool[0].width = 1280;
                expected = 1;
            }
            else if (scenario == 25)
            {
                View.localClient = 1;
                expected = 1;
            }
            else if (scenario == 26)
            {
                Frame(2, 33);
                expected = 1;
            }
            else if (scenario == 27)
            {
                if (!StampFrame(1, 18))
                    return 512;
                Frame(1, 44);
                expected = 1;
            }
            else if (scenario == 28)
            {
                BadIdentity = 1;
                expected = 1;
            }
            if (!StampFrame(3, retainedToken))
                return 512;
            Frame(3, 55);
            if (Draws != expected || (expected == 2 && Drawn != 11) ||
                Copies != (scenario == 27 ? 2u : 1u))
                return 4096;
            BadIdentity = 0;
            if (scenario == 21)
            {
                if (!StampFrame(3, retainedToken))
                    return 512;
                Frame(3, 66);
                if (Draws != 3 || Drawn != 11 || Copies != 1)
                    return 4096;
            }
            DW_AltKillcamRender_Disarm(0);
            DW_AltKillcamRender_Disarm(1);
            Frame(3, 77);
            View.localClient = 0;
            Frame(2, 77);
            return Error;
        }
        if (scenario == 16 || scenario == 17)
        {
            if (scenario == 17 && !StampFrame(2, 99))
                return 512;
            Frame(2, 22);
            if (!StampFrame(2, 17))
                return 512;
            Frame(2, 22);
            DW_AltKillcamRender_Disarm(0);
            Frame(2, 22);
            return Error | (Draws || Destroys != 1 ? 256 : 0);
        }
        if (scenario == 6)
        {
            Pool[0].width = 1280;
            Pool[0].height = 720;
            if (!StampFrame(1, 18))
                return 512;
            Frame(1, 33);
            if (Destroys != 1 || Submits != 1 || Waits != 1)
                return 2048;
        }
        if (scenario == 7)
        {
            DW_AltKillcamRender_DestroyGlobalTargets();
            return Error | (Destroys != 1 || Resets != 1 ? 256 : 0);
        }
        if (scenario == 8)
        {
            Pool[1].imageName = "unrelated replacement";
            DW_AltKillcamRender_Disarm(0);
            Frame(2, 22);
            return Error | (Destroys || Draws || Submits ? 256 : 0);
        }
        const DWAltKillcamViewport outside{1900, 1000, 480, 270};
        if (scenario == 14)
            *reinterpret_cast<uint32_t *>(Backend[0] + 33256) = 2;
        if (!StampFrame(2,
                        scenario == 2   ? 99
                        : scenario == 6 ? 18
                                        : 17,
                        scenario == 3 ? &outside : nullptr))
            return 512;
        Frame(2, 22);
        unsigned expected = scenario == 2 || scenario == 3 || scenario == 14 ? 0 : 1;
        if (Draws != expected || (expected && Drawn != (scenario == 6 ? 33 : 11)) ||
            Source.inputImage != reinterpret_cast<void *>(0x4567) ||
            memcmp(&Source.viewport, &View.displayViewport, 16) ||
            memcmp(&StateViewport(), &View.displayViewport, 16) ||
            memcmp(&Scissor(), &View.displayViewport, 16))
            return 4096;
        DW_AltKillcamRender_Disarm(0);
        Frame(2, 22);
        return Error | (Destroys != (scenario == 6 ? 2u : 1u) ? 8192 : 0);
    }
    __declspec(dllexport) void Test_FallbackCase(unsigned sourceWidth, unsigned sourceHeight,
                                                 unsigned outputWidth, unsigned outputHeight,
                                                 float scale, unsigned mask)
    {
        uint16_t attachments[6] = {2,
                                   7,
                                   uint16_t(mask & 1 ? 8 : 0),
                                   uint16_t(mask & 2 ? 9 : 0),
                                   uint16_t(mask & 4 ? 10 : 0),
                                   uint16_t(mask & 8 ? 11 : 0)};
        ResolutionScale = scale;
        memset(FallbackResults, 0, sizeof(FallbackResults));
        Pool[0].width = uint16_t(outputWidth);
        Pool[0].height = uint16_t(outputHeight);
        Pool[1].width = uint16_t(sourceWidth);
        Pool[1].height = uint16_t(sourceHeight);
        Task.attachments = attachments;
        Task.targets = {1, 0, {1, 0, 0, 0}, 0, 0};
        AKR_FinalCompositeNative(&Ctx, &Task, &View, Backend[0]);
    }
    __declspec(dllexport) int Test_FallbackResult(unsigned index)
    {
        return FallbackResults[index];
    }
}
