#include "DW_AltKillcam.h"
#include "DW_AltKillcamBindings.h"
#include "DW_AltKillcamRender.h"
#include "replay_dvar.h"

#include <string.h>

namespace
{
    const dvar_t *s_option;
    uint64_t s_token;
    uint32_t s_ownerScope[2];
    bool s_renderArmed[2];
    bool s_busy;

    struct StreamingScope
    {
        void *backend;
        int32_t frame, viewIndex;
        uint32_t local;
        bool active;
    };

    StreamingScope s_objectStreaming;

    template <typename T> T &Field(void *base, size_t offset)
    {
        return *reinterpret_cast<T *>(static_cast<uint8_t *>(base) + offset);
    }

    struct Camera
    {
        void *globals;
        void *snapshot;
        DWAltKillcamRefdef *refdef;
        uint32_t local;
        int32_t type;
        bool liveObject;
    };

    struct ObjectCamera
    {
        DWAltKillcamRefdef refdef;
        void *globals;
        void *snapshot;
        int32_t time;
        int32_t entity;
        int32_t type;
        float angles[3];
        bool valid;
    };

    ObjectCamera s_objectCamera[2];

    struct ReplaySession
    {
        void *globals;
        int32_t startTime, client;
        uint64_t lastObjectToken;
        bool active;
        bool hasObjectPose;
    };

    ReplaySession s_replay[2];
    void Disarm(uint32_t local);

    void ClearReplay(uint32_t local)
    {
        s_replay[local] = {};
        s_objectCamera[local].valid = false;
        Disarm(local);
    }

    bool GetCamera(uint32_t local, Camera *result, bool requireGraph = true)
    {
        if (local >= 2 || !AK_IsMainThread())
            return false;
        if (!s_option || s_option->current.integer != 1 || AK_GameMode() != 2 ||
            (requireGraph && !DW_AltKillcamRender_SupportsCurrentGraph()))
        {
            ClearReplay(local);
            return false;
        }
        void *cg = AK_CgGlobals[local];
        if (!cg || Field<int32_t>(cg, 25632) != static_cast<int32_t>(local) ||
            !Field<int32_t>(cg, 533720) || !Field<int32_t>(cg, 12064))
        {
            ClearReplay(local);
            return false;
        }
        const auto &state = Field<DWAltKillcamNativeState>(cg, 533720);
        const int32_t type = state.objectType;
        void *snapshot = Field<void *>(cg, 26000);
        const int32_t client = Field<int32_t>(cg, 456);
        if (!snapshot || client < 0 || client >= AK_MaxClients ||
            Field<int32_t>(snapshot, 488) != client)
        {
            ClearReplay(local);
            return false;
        }
        auto *refdef = reinterpret_cast<DWAltKillcamRefdef *>(static_cast<uint8_t *>(cg) + 26624);
        if (refdef->localClientNum != static_cast<int32_t>(local) ||
            refdef->displayViewport[2] < 64 || refdef->displayViewport[3] < 64)
        {
            ClearReplay(local);
            return false;
        }
        auto &replay = s_replay[local];
        if (replay.active && (replay.globals != cg || replay.startTime != state.startTime ||
                              replay.client != client))
            ClearReplay(local);
        const int32_t entity = state.entity;
        void *entities = AK_EntitySystems[local] ? Field<void *>(AK_EntitySystems[local], 16) : nullptr;
        const bool live = type >= 1 && type <= 9 && entity >= 0 && entity < 2047 && entities &&
                          (Field<uint8_t>(entities, 752 * entity + 640) & 1);
        if (type < 0 || type > 9)
        {
            ClearReplay(local);
            return false;
        }
        if (!replay.active && !live)
            return false;
        if (!replay.active)
            replay = {cg, state.startTime, client, 0, true, false};
        *result = {cg, snapshot, refdef, local, type, live};
        return true;
    }

    class OwnerScope
    {
        uint32_t local_;
        bool active_;

      public:
        explicit OwnerScope(uint32_t local) : local_(local), active_(false)
        {
            Camera camera;
            active_ = GetCamera(local, &camera);
            if (active_)
                ++s_ownerScope[local];
        }

        ~OwnerScope()
        {
            if (active_)
                --s_ownerScope[local_];
        }
    };

    bool OwnerView(uint32_t local)
    {
        return local < 2 && AK_IsMainThread() && s_ownerScope[local];
    }

    void CopyCameraView(DWAltKillcamRefdefView *destination, const DWAltKillcamRefdefView *source)
    {
        uint32_t origin[3];
        for (uint32_t i = 0; i < 3; ++i)
        {
            const auto *address = &source->encodedOrigin[i];
            const uint32_t value = source->originKey ^
                                   static_cast<uint32_t>(reinterpret_cast<uintptr_t>(address));
            origin[i] = *address ^ (value * (value + 2));
        }
        memcpy(destination, source, sizeof(*destination));
        destination->originKey += destination->originSeed;
        for (uint32_t i = 0; i < 3; ++i)
        {
            auto *address = &destination->encodedOrigin[i];
            const uint32_t value = destination->originKey ^
                                   static_cast<uint32_t>(reinterpret_cast<uintptr_t>(address));
            *address = origin[i] ^ (value * (value + 2));
        }
    }

    void CopyCamera(DWAltKillcamRefdef *destination, const DWAltKillcamRefdef *source)
    {
        memcpy(destination, source, sizeof(*destination));
        CopyCameraView(&destination->view, &source->view);
    }

    void ContinueObjectCamera(DWAltKillcamRefdef *destination, const Camera &camera)
    {
        const auto &last = s_objectCamera[camera.local].refdef;
        // Keep the final camera pose, not its pixels or an expired frame's
        // renderer inputs. Time, viewport, effects and other frame data come
        // from the current replay; no destroyed entity is accessed here.
        CopyCamera(destination, camera.refdef);
        CopyCameraView(&destination->view, &last.view);
        memcpy(destination->viewOffset, last.viewOffset, sizeof(destination->viewOffset));
        memcpy(destination->previousViewOffset, last.viewOffset,
               sizeof(destination->previousViewOffset));
    }

    struct Scene
    {
        DWAltKillcamSceneDObj objects[512];
        DWAltKillcamSceneModel models[1024];
        DWAltKillcamSceneBrush brushes[512];
        uint16_t objectIndex[4096], modelIndex[4096];
        int32_t objectCount, modelCount, objectModelCount, brushCount, entityCount;
    };

    Scene s_scene;

    bool SaveScene()
    {
        if (!AK_SceneObjects || !AK_SceneObjectIndex || !AK_SceneModelIndex ||
            AK_SceneObjectCount < 0 || AK_SceneObjectCount > 512 || AK_SceneModelCount < 0 ||
            AK_SceneModelCount > 1024 || AK_SceneObjectModelCount < 0 ||
            AK_SceneObjectModelCount > AK_SceneModelCount || AK_SceneBrushCount < 0 ||
            AK_SceneBrushCount > 512 || AK_SceneEntityCount < 0 || AK_SceneEntityCount > 1024)
            return false;
        s_scene.objectCount = AK_SceneObjectCount;
        s_scene.modelCount = AK_SceneModelCount;
        s_scene.objectModelCount = AK_SceneObjectModelCount;
        s_scene.brushCount = AK_SceneBrushCount;
        s_scene.entityCount = AK_SceneEntityCount;
        memcpy(s_scene.objects, AK_SceneObjects, sizeof(s_scene.objects[0]) * s_scene.objectCount);
        memcpy(s_scene.models, AK_SceneModels, sizeof(s_scene.models[0]) * s_scene.modelCount);
        memcpy(s_scene.brushes, AK_SceneBrushes, sizeof(s_scene.brushes[0]) * s_scene.brushCount);
        memcpy(s_scene.objectIndex, AK_SceneObjectIndex, sizeof(s_scene.objectIndex));
        memcpy(s_scene.modelIndex, AK_SceneModelIndex, sizeof(s_scene.modelIndex));
        return true;
    }

    bool IsViewmodel(uint32_t entity)
    {
        return entity == 2048 || entity == 2049;
    }

    void ReserveView(Camera &camera)
    {
        int32_t viewIndex;
        AK_NextView(&viewIndex);
        Field<int32_t>(camera.globals, 167080) = viewIndex;
    }

    class ObjectStreamingScope
    {
      public:
        explicit ObjectStreamingScope(const Camera &camera)
        {
            s_objectStreaming = {AK_Backend,
                                 Field<int32_t>(AK_Backend, 33256),
                                 Field<int32_t>(camera.globals, 167080),
                                 camera.local,
                                 true};
        }

        ~ObjectStreamingScope()
        {
            s_objectStreaming = {};
        }
    };

    // Complete native CL_RenderScene setup after its already-reserved view index.
    // The ordinary/default-off path still calls the byte-faithful native clone.
    void RenderReserved(Camera &camera,
                        uint32_t drawType,
                        int32_t viewportType,
                        int32_t atlasTime = AK_RealTime(),
                        bool cameraCut = false)
    {
        AK_TextureAtlasTime(atlasTime);
        AK_SceneSubmitted = 1;
        DWAltKillcamFeatures features;
        AK_DefaultFeatures(&features);
        features.viewportType = viewportType;
        features.flags40 |= 0x6000;
        features.flags40 =
            (features.flags40 & 0xcfffffff) | ((Field<uint8_t>(camera.globals, 168533) & 1) << 28);
        if (!AK_IsPipView())
            features.flags40 =
                (features.flags40 & 0xdfffffff) |
                (static_cast<int32_t>(camera.local) == AK_FirstClient ? 0x20000000 : 0);
        uint8_t exposure[48];
        memcpy(exposure, static_cast<uint8_t *>(camera.globals) + 534460, sizeof(exposure));
        AK_Exposure(exposure);
        Field<int32_t>(&features, 24) = AK_SceneFrame();
        // Replay keys task-graph temporal resources by local client, even
        // though its matrix history also distinguishes the viewport type.
        // Mark both paired cameras as native cuts so neither can reuse the
        // other camera's image. Restore the caller's camera flag immediately.
        const uint8_t teleported = camera.refdef->playerTeleported;
        if (cameraCut)
            camera.refdef->playerTeleported = 1;
        AK_RenderNative(camera.refdef, AK_DefaultLod, drawType, &features);
        camera.refdef->playerTeleported = teleported;
    }

    void ObjectScene(uint32_t local)
    {
        memset(AK_SceneObjectIndex, 0xff, sizeof(s_scene.objectIndex));
        memset(AK_SceneModelIndex, 0xff, sizeof(s_scene.modelIndex));
        int32_t count = 0;
        for (int32_t i = 0; i < s_scene.objectCount; ++i)
        {
            const auto &object = s_scene.objects[i];
            const uint32_t entity = (object.packedEntity >> 10) & 4095;
            if (IsViewmodel(entity))
                continue;
            AK_SceneObjects[count] = object;
            AK_SceneObjectIndex[entity] = static_cast<uint16_t>(count++);
        }
        AK_SceneObjectCount = count;
        count = 0;
        int32_t prefix = 0;
        for (int32_t i = 0; i < s_scene.modelCount; ++i)
        {
            const auto &model = s_scene.models[i];
            const uint32_t entity = (model.packedEntity >> 10) & 4095;
            if (IsViewmodel(entity))
                continue;
            AK_SceneModels[count] = model;
            AK_SceneModelIndex[entity] = static_cast<uint16_t>(count++);
            if (i < s_scene.objectModelCount)
                ++prefix;
        }
        AK_SceneModelCount = count;
        AK_SceneObjectModelCount = prefix;
        AK_ClearSceneView(local);
        AK_MarkScene();
        AK_ResetScene();
    }

    void RestoreScene(uint32_t local)
    {
        memcpy(AK_SceneObjects, s_scene.objects, sizeof(s_scene.objects[0]) * s_scene.objectCount);
        memcpy(AK_SceneModels, s_scene.models, sizeof(s_scene.models[0]) * s_scene.modelCount);
        memcpy(AK_SceneBrushes, s_scene.brushes, sizeof(s_scene.brushes[0]) * s_scene.brushCount);
        memcpy(AK_SceneObjectIndex, s_scene.objectIndex, sizeof(s_scene.objectIndex));
        memcpy(AK_SceneModelIndex, s_scene.modelIndex, sizeof(s_scene.modelIndex));
        AK_SceneObjectCount = s_scene.objectCount;
        AK_SceneModelCount = s_scene.modelCount;
        AK_SceneObjectModelCount = s_scene.objectModelCount;
        AK_SceneBrushCount = s_scene.brushCount;
        AK_SceneEntityCount = s_scene.entityCount;
        AK_ClearSceneView(local);
        AK_MarkScene();
        AK_ResetScene();
    }

    void Disarm(uint32_t local)
    {
        if (s_renderArmed[local])
        {
            DW_AltKillcamRender_Disarm(local);
            s_renderArmed[local] = false;
        }
    }

    bool PendingCamera(const Camera &camera)
    {
        const auto &object = s_objectCamera[camera.local];
        return object.valid && object.globals == camera.globals &&
               object.snapshot == camera.snapshot &&
               object.time == Field<int32_t>(camera.globals, 26020) &&
               object.entity == Field<int32_t>(camera.globals, 533740) &&
               object.type == camera.type;
    }

    void RestoreObjectCamera(uint32_t local, DWAltKillcamRefdef *refdef)
    {
        Camera camera;
        if (!GetCamera(local, &camera, false) || camera.refdef != refdef || !PendingCamera(camera))
            return;
        const auto &object = s_objectCamera[local];
        CopyCamera(refdef, &object.refdef);
        memcpy(
            static_cast<uint8_t *>(camera.globals) + 29856, object.angles, sizeof(object.angles));
        if (SaveScene())
            ObjectScene(local);
    }
} // namespace

extern "C" void DW_AltKillcam_Init()
{
    if (s_option || !AK_IsMainThread())
        return;
    Dvar_BeginPermanentRegistration();
    s_option = Dvar_RegisterInt(
        "alt_killcam", 0, 0, 1, 1, "Show the recorded killer with the object killcam in a corner.");
    Dvar_EndPermanentRegistration();
}

extern "C" bool DW_AltKillcam_EntityView(uint32_t local)
{
    if (OwnerView(local))
        return false;
    void *cg = AK_CgGlobals[local];
    return Field<int32_t>(cg, 533720) && Field<int32_t>(cg, 533724);
}

extern "C" bool DW_AltKillcam_EntityFov(uint32_t local)
{
    if (OwnerView(local))
        return false;
    void *cg = AK_CgGlobals[local];
    const int32_t type = Field<int32_t>(cg, 533724);
    return Field<int32_t>(cg, 533720) && (type == 1 || type == 3 || type == 6 || type == 9);
}

extern "C" void DW_AltKillcam_Predict(uint32_t local)
{
    OwnerScope scope(local);
    AK_OriginalPredict(local);
}

extern "C" void DW_AltKillcam_CalcView(uint32_t local)
{
    OwnerScope scope(local);
    AK_OriginalCalcView(local);
}

extern "C" void DW_AltKillcam_WeaponAnim(uint32_t local)
{
    OwnerScope scope(local);
    AK_OriginalWeaponAnim(local);
}

extern "C" void DW_AltKillcam_AddViewWeapon(uint32_t local)
{
    OwnerScope scope(local);
    AK_OriginalAddViewWeapon(local);
}

extern "C" uint32_t DW_AltKillcam_UpdateThirdPerson(uint32_t local)
{
    OwnerScope scope(local);
    return AK_OriginalUpdateThirdPerson(local);
}

extern "C" void DW_AltKillcam_UpdateStreaming(DWAltKillcamSceneView *view)
{
    // Native streaming counts rendered clients, rather than secondary camera
    // scenes. Registering this extra scene as another client makes Replay's
    // one-client saved-view worker read a position float as a view count.
    if (AK_IsMainThread() && s_objectStreaming.active && view &&
        view->backend == s_objectStreaming.backend && view->backend == AK_Backend &&
        view->localClient == static_cast<int32_t>(s_objectStreaming.local) &&
        view->viewIndex == s_objectStreaming.viewIndex &&
        Field<int32_t>(view->backend, 33256) == s_objectStreaming.frame)
    {
        AK_WaitWorkerType(89);
        return;
    }
    AK_OriginalUpdateStreaming(view);
}

extern "C" void DW_AltKillcam_LerpView(uint32_t local)
{
    Camera camera;
    if (!GetCamera(local, &camera))
    {
        if (local < 2 && AK_IsMainThread())
            s_objectCamera[local].valid = false;
        AK_OriginalLerpView(local);
        return;
    }
    // Run the original interpolation at its ordinary place in the MP frame.
    // Its object history writes remain native even if a later extra render is
    // rejected. Only the temporary camera and angles are restored for main.
    DWAltKillcamRefdef mainCamera;
    CopyCamera(&mainCamera, camera.refdef);
    float angles[3];
    memcpy(angles, static_cast<uint8_t *>(camera.globals) + 29856, sizeof(angles));
    const auto thirdPerson = Field<DWAltKillcamThirdPersonState>(camera.globals, 311392);
    if (camera.liveObject)
        AK_UpdateObjectCamera(local, camera.type);
    AK_OriginalLerpView(local);
    Field<DWAltKillcamThirdPersonState>(camera.globals, 311392) = thirdPerson;
    if (!camera.liveObject)
    {
        s_objectCamera[local].valid = false;
        CopyCamera(camera.refdef, &mainCamera);
        memcpy(static_cast<uint8_t *>(camera.globals) + 29856, angles, sizeof(angles));
        return;
    }
    auto &object = s_objectCamera[local];
    CopyCamera(&object.refdef, camera.refdef);
    object.globals = camera.globals;
    object.snapshot = camera.snapshot;
    object.time = Field<int32_t>(camera.globals, 26020);
    object.entity = Field<int32_t>(camera.globals, 533740);
    object.type = camera.type;
    memcpy(object.angles, static_cast<uint8_t *>(camera.globals) + 29856, sizeof(object.angles));
    object.valid = true;
    s_replay[local].hasObjectPose = true;
    CopyCamera(camera.refdef, &mainCamera);
    memcpy(static_cast<uint8_t *>(camera.globals) + 29856, angles, sizeof(angles));
}

extern "C" void DW_AltKillcam_RenderScene(uint32_t local,
                                          DWAltKillcamRefdef *refdef,
                                          uint32_t drawType)
{
    if (!AK_IsMainThread())
    {
        AK_OriginalRenderScene(local, refdef, drawType);
        return;
    }
    Camera camera;
    if (s_busy || drawType < 1 || drawType > 3 || !GetCamera(local, &camera) ||
        refdef != camera.refdef || AK_ViewCount < 0 || AK_ViewCount > 4 ||
        (camera.liveObject && !PendingCamera(camera)) ||
        (s_replay[local].hasObjectPose && !SaveScene()))
    {
        if (local < 2)
        {
            RestoreObjectCamera(local, refdef);
            s_objectCamera[local].valid = false;
            Disarm(local);
        }
        AK_OriginalRenderScene(local, refdef, drawType);
        return;
    }
    s_busy = true;
    const int32_t width = refdef->displayViewport[2];
    const int32_t height = refdef->displayViewport[3];
    DWAltKillcamViewport inset{
        refdef->displayViewport[0] + width - width / 4 - width / 20,
        refdef->displayViewport[1] + height / 5,
        width / 4,
        height / 4,
    };
    if (!s_replay[local].hasObjectPose)
    {
        ReserveView(camera);
        Disarm(local);
        RenderReserved(camera, drawType, 0);
        s_busy = false;
        return;
    }
    DWAltKillcamRefdef mainCamera, objectCamera;
    CopyCamera(&mainCamera, refdef);
    if (camera.liveObject)
        CopyCamera(&objectCamera, &s_objectCamera[local].refdef);
    else
        ContinueObjectCamera(&objectCamera, camera);
    uint64_t token = ++s_token;
    if (!token)
        token = ++s_token;
    ReserveView(camera);
    const int32_t atlasTime = AK_RealTime();
    const bool stamped =
        DW_AltKillcamRender_Stamp(AK_Backend, local, DWAltKillcamBatch::Object, token, &inset);
    if (!stamped)
    {
        RestoreObjectCamera(local, refdef);
        s_objectCamera[local].valid = false;
        Disarm(local);
        RenderReserved(camera, drawType, 0, atlasTime);
        s_busy = false;
        return;
    }
    s_objectCamera[local].valid = false;
    s_renderArmed[local] = true;
    s_replay[local].lastObjectToken = token;
    ObjectScene(local);
    CopyCamera(refdef, &objectCamera);
    AK_SetLodOrigin(refdef, AK_DefaultLod);
    {
        ObjectStreamingScope streaming(camera);
        RenderReserved(camera, 1, 1, atlasTime, true);
    }
    AK_EndList();
    AK_EndBatch();
    // Complete the native renderer CPU batch before reusing shared scene
    // records. BeginFrame's ready flag alone is not a consumer fence.
    AK_SyncRenderThread();
    AK_BeginBatch(local);
    RestoreScene(local);
    CopyCamera(refdef, &mainCamera);
    AK_SetLodOrigin(refdef, AK_DefaultLod);
    ReserveView(camera);
    if (!DW_AltKillcamRender_Stamp(AK_Backend, local, DWAltKillcamBatch::Killer, token, &inset))
        Disarm(local);
    RenderReserved(camera, drawType == 3 ? 2 : drawType, 0, atlasTime, true);
    s_busy = false;
}
