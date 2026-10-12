#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include "DW_AltKillcam.cpp"

static int cases, registrations, begins, ends;
static bool mainThread = true, failObject, failKiller, pip;
static bool supportsGraph = true;
static uint8_t gameMode = 2;
static dvar_t option;
static uint8_t globals[2][540000], snapshots[2][1000], systems[2][32], entities[2][752 * 2048];
static uint8_t replacementGlobals[540000];
static DWAltKillcamSceneDObj objects[512];
static uint16_t objectIndices[4096], modelIndices[4096];
static int originalCounts[7], interpolations, cameraUpdates, extraRenders, disarms;
static bool insideEntity[5], insideFov[5];
static std::string trace;
static uint64_t objectToken;
static uint32_t stampedLocal;
static int32_t reservedIndex;
static bool capturedMain, capturedObject;
static DWAltKillcamViewport stampedInset;
static DWAltKillcamFeatures submittedFeatures;
static uint8_t backends[2][40000];
static int streamingUpdates;
static int streamingWaits;
static uint32_t thirdPersonReturn = 1;
static bool expectCameraCut;
static int retainedStamps;
static int32_t submittedObjectTime;
static uint32_t submittedObjectFrameTag;
static uint8_t submittedObjectSceneTag;
static int32_t submittedObjectViewport[4];

#define REQUIRE(x)                                                                                 \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
        {                                                                                          \
            std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                           \
            std::exit(1);                                                                          \
        }                                                                                          \
    } while (0)
extern "C"
{
    void *AK_CgGlobals[2];
    void *AK_Backend;
    void *AK_EntitySystems[2];
    extern const float AK_DefaultLod = 1.0f;
    int32_t AK_MaxClients = 200, AK_ViewCount, AK_SceneSubmitted, AK_FirstClient;
    int32_t AK_SceneEntityCount, AK_SceneObjectCount, AK_SceneModelCount;
    int32_t AK_SceneBrushCount, AK_SceneObjectModelCount;
    DWAltKillcamSceneDObj *AK_SceneObjects = objects;
    DWAltKillcamSceneModel AK_SceneModels[1024];
    DWAltKillcamSceneBrush AK_SceneBrushes[512];
    uint16_t *AK_SceneObjectIndex = objectIndices, *AK_SceneModelIndex = modelIndices;

    bool AK_IsMainThread()
    {
        return mainThread;
    }

    uint8_t AK_GameMode()
    {
        return gameMode;
    }

    void Dvar_BeginPermanentRegistration()
    {
        ++begins;
    }

    void Dvar_EndPermanentRegistration()
    {
        ++ends;
    }

    dvar_t *Dvar_RegisterInt(
        const char *name, int32_t value, int32_t min, int32_t max, uint32_t flags, const char *)
    {
        REQUIRE(std::strcmp(name, "alt_killcam") == 0);
        REQUIRE(value == 0 && min == 0 && max == 1 && flags == 1);
        ++registrations;
        option.current.integer = value;
        return &option;
    }
}

static void SetOrigin(DWAltKillcamRefdef *r, float x)
{
    for (int i = 0; i < 3; ++i)
    {
        const float component = x + static_cast<float>(i * 17);
        uint32_t bits;
        std::memcpy(&bits, &component, 4);
        const uint32_t key =
            r->view.originKey ^
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&r->view.encodedOrigin[i]));
        r->view.encodedOrigin[i] = bits ^ (key * (key + 2));
    }
}

static float Origin(const DWAltKillcamRefdef *r, int component = 0)
{
    const uint32_t key =
        r->view.originKey ^
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&r->view.encodedOrigin[component]));
    const uint32_t bits = r->view.encodedOrigin[component] ^ (key * (key + 2));
    float x;
    std::memcpy(&x, &bits, 4);
    return x;
}

static DWAltKillcamRefdef *Ref(uint32_t l)
{
    return reinterpret_cast<DWAltKillcamRefdef *>(globals[l] + 26624);
}

extern "C"
{
    void AK_OriginalPredict(uint32_t l)
    {
        ++originalCounts[0];
        insideEntity[0] = DW_AltKillcam_EntityView(l);
        insideFov[0] = DW_AltKillcam_EntityFov(l);
        REQUIRE(!DW_AltKillcam_EntityView(l) || !OwnerView(l));
    }

    void AK_OriginalCalcView(uint32_t l)
    {
        ++originalCounts[1];
        insideEntity[1] = DW_AltKillcam_EntityView(l);
        insideFov[1] = DW_AltKillcam_EntityFov(l);
        REQUIRE(!DW_AltKillcam_EntityView(l) || !OwnerView(l));
    }

    void AK_OriginalWeaponAnim(uint32_t l)
    {
        ++originalCounts[2];
        insideEntity[2] = DW_AltKillcam_EntityView(l);
        insideFov[2] = DW_AltKillcam_EntityFov(l);
        REQUIRE(!DW_AltKillcam_EntityView(l) || !OwnerView(l));
    }

    void AK_OriginalAddViewWeapon(uint32_t l)
    {
        ++originalCounts[3];
        insideEntity[3] = DW_AltKillcam_EntityView(l);
        insideFov[3] = DW_AltKillcam_EntityFov(l);
        REQUIRE(!DW_AltKillcam_EntityView(l) || !OwnerView(l));
    }

    uint32_t AK_OriginalUpdateThirdPerson(uint32_t l)
    {
        ++originalCounts[6];
        insideEntity[4] = DW_AltKillcam_EntityView(l);
        insideFov[4] = DW_AltKillcam_EntityFov(l);
        REQUIRE(!OwnerView(l) || (!insideEntity[4] && !insideFov[4]));
        return thirdPersonReturn;
    }

    void AK_OriginalLerpView(uint32_t l)
    {
        ++originalCounts[4];
        ++interpolations;
        Field<DWAltKillcamThirdPersonState>(globals[l], 311392) = {1, 0xf00d1234U, 1, 1};
        SetOrigin(Ref(l), Origin(Ref(l)) + 1);
    }

    void AK_OriginalRenderScene(uint32_t local, DWAltKillcamRefdef *, uint32_t)
    {
        DWAltKillcamSceneView view{};
        view.backend = AK_Backend;
        view.viewIndex = Field<int32_t>(globals[local], 167080);
        view.localClient = static_cast<int32_t>(local);
        DW_AltKillcam_UpdateStreaming(&view);
        ++originalCounts[5];
        trace += 'F';
    }

    void AK_UpdateObjectCamera(uint32_t l, int32_t type)
    {
        ++cameraUpdates;
        REQUIRE(type >= 1 && type <= 9);
        Field<DWAltKillcamThirdPersonState>(globals[l], 311392) = {1, 0xbaad5678U, 1, 1};
        SetOrigin(Ref(l), 700);
    }

    void AK_SetLodOrigin(const DWAltKillcamRefdef *, float lod)
    {
        REQUIRE(lod == 1);
        trace += 'L';
    }

    void AK_DefaultFeatures(DWAltKillcamFeatures *f)
    {
        std::memset(f, 0, sizeof(*f));
    }

    void AK_NextView(int32_t *index)
    {
        *index = AK_ViewCount++;
        reservedIndex = *index;
        trace += 'N';
    }

    int32_t AK_RealTime()
    {
        return 321;
    }

    void AK_TextureAtlasTime(int32_t t)
    {
        REQUIRE(t == 321);
    }

    bool AK_IsPipView()
    {
        return pip;
    }

    void AK_Exposure(const void *) {}

    int32_t AK_SceneFrame()
    {
        return 42;
    }

    void AK_RenderNative(const DWAltKillcamRefdef *r,
                         float lod,
                         uint32_t draw,
                         const DWAltKillcamFeatures *f)
    {
        DWAltKillcamSceneView view{};
        view.backend = AK_Backend;
        view.viewIndex = reservedIndex;
        view.localClient = r->localClientNum;
        DW_AltKillcam_UpdateStreaming(&view);
        REQUIRE(lod == 1 && draw >= 1 && draw <= 3);
        REQUIRE(f->flags40 ==
                (0x6000U |
                 (Field<uint8_t>(globals[r->localClientNum], 168533) & 1 ? 0x10000000U : 0) |
                 (!pip && r->localClientNum == AK_FirstClient ? 0x20000000U : 0)));
        REQUIRE(Field<int32_t>(const_cast<DWAltKillcamFeatures *>(f), 24) == 42);
        REQUIRE(Field<int32_t>(globals[r->localClientNum], 167080) == reservedIndex);
        REQUIRE(bool(r->playerTeleported) == expectCameraCut);
        ++extraRenders;
        trace += 'R';
        submittedFeatures = *f;
        if (f->viewportType == 1 || failObject)
        {
            capturedObject = true;
            submittedObjectTime = r->time;
            submittedObjectFrameTag = r->unknown3228;
            submittedObjectSceneTag = AK_SceneObjects[0].unknown0[0];
            std::memcpy(submittedObjectViewport, r->displayViewport, sizeof(submittedObjectViewport));
            REQUIRE((draw == 1 || failObject) && Origin(r) == 701);
            REQUIRE(AK_SceneObjectCount == 1 && AK_SceneObjectIndex[17] == 0);
            REQUIRE(AK_SceneObjectIndex[2048] == 0xffff && AK_SceneObjectIndex[2049] == 0xffff);
            REQUIRE(AK_SceneModelCount == 1 && AK_SceneObjectModelCount == 1);
        }
        else
        {
            capturedMain = true;
            REQUIRE(Origin(r) == 100 + r->localClientNum);
            REQUIRE(AK_SceneObjectCount == 3 && AK_SceneModelCount == 2);
            REQUIRE(AK_SceneObjectIndex[2048] == 1 && AK_SceneObjectIndex[2049] == 2);
        }
    }

    void AK_EndList()
    {
        trace += 'E';
    }

    void AK_EndBatch()
    {
        trace += 'D';
        AK_Backend = nullptr;
    }

    void AK_SyncRenderThread()
    {
        REQUIRE(trace.back() == 'D');
        trace += 'C';
    }

    void AK_BeginBatch(uint32_t)
    {
        REQUIRE(trace.back() == 'C');
        trace += 'B';
        AK_Backend = backends[1];
    }

    void AK_MarkScene()
    {
        trace += 'M';
    }

    void AK_ResetScene()
    {
        trace += 'X';
    }

    void AK_ClearSceneView(uint32_t)
    {
        trace += 'V';
    }

    bool DW_AltKillcamRender_Stamp(void *backend,
                                   uint32_t local,
                                   DWAltKillcamBatch phase,
                                   uint64_t token,
                                   const DWAltKillcamViewport *inset)
    {
        REQUIRE(backend && token && inset->width > 0 && inset->height > 0);
        REQUIRE(trace.back() == 'N');
        REQUIRE(Field<int32_t>(globals[local], 167080) == reservedIndex);
        if (phase == DWAltKillcamBatch::Object)
        {
            REQUIRE(token > objectToken);
            objectToken = token;
            stampedLocal = local;
            stampedInset = *inset;
            trace += 'O';
            return !failObject;
        }
        REQUIRE(phase == DWAltKillcamBatch::Killer || phase == DWAltKillcamBatch::RetainedKiller);
        REQUIRE(stampedLocal == local && token == objectToken);
        REQUIRE(std::memcmp(inset, &stampedInset, 16) == 0);
        if (phase == DWAltKillcamBatch::RetainedKiller)
        {
            ++retainedStamps;
            trace += 'T';
            return !failKiller;
        }
        trace += 'K';
        return !failKiller;
    }

    void DW_AltKillcamRender_Disarm(uint32_t)
    {
        ++disarms;
    }

    bool DW_AltKillcamRender_SupportsCurrentGraph()
    {
        return supportsGraph;
    }

    void AK_OriginalUpdateStreaming(DWAltKillcamSceneView *)
    {
        ++streamingUpdates;
    }

    void AK_WaitWorkerType(uint32_t type)
    {
        REQUIRE(type == 89 && s_objectStreaming.active);
        ++streamingWaits;
    }
}

static void Reset(uint32_t local = 0, int type = 3)
{
    std::memset(globals, 0, sizeof(globals));
    std::memset(snapshots, 0, sizeof(snapshots));
    std::memset(originalCounts, 0, sizeof(originalCounts));
    std::memset(s_objectCamera, 0, sizeof(s_objectCamera));
    std::memset(s_renderArmed, 0, sizeof(s_renderArmed));
    std::memset(s_replay, 0, sizeof(s_replay));
    for (int l = 0; l < 2; ++l)
    {
        AK_CgGlobals[l] = globals[l];
        AK_EntitySystems[l] = systems[l];
        Field<void *>(systems[l], 16) = entities[l];
        Field<int32_t>(globals[l], 25632) = l;
        Field<int32_t>(globals[l], 533720) = 1;
        Field<int32_t>(globals[l], 533724) = type;
        Field<int32_t>(globals[l], 533728) = 900;
        Field<DWAltKillcamThirdPersonState>(globals[l], 311392) = {0, 0x12344321U, 0, 0};
        Field<int32_t>(globals[l], 12064) = 50;
        Field<void *>(globals[l], 26000) = snapshots[l];
        Field<int32_t>(globals[l], 456) = 3 + l;
        Field<int32_t>(snapshots[l], 488) = 3 + l;
        Field<int32_t>(globals[l], 533740) = 17;
        Field<int32_t>(globals[l], 26020) = 1000;
        Field<uint8_t>(entities[l], 752 * 17 + 640) = 1;
        auto *r = Ref(l);
        r->localClientNum = l;
        r->displayViewport[0] = l * 1920;
        r->displayViewport[2] = 1920;
        r->displayViewport[3] = 1080;
        r->view.originKey = 0x12345678;
        r->view.originSeed = 0x11112222;
        SetOrigin(r, 100 + static_cast<float>(l));
        r->unknown3228 = 0x87654321;
        r->time = 777;
    }
    std::memset(objects, 0, sizeof(objects));
    std::memset(AK_SceneModels, 0, sizeof(AK_SceneModels));
    std::memset(objectIndices, 0xff, sizeof(objectIndices));
    std::memset(modelIndices, 0xff, sizeof(modelIndices));
    objects[0].packedEntity = 17 << 10;
    objects[1].packedEntity = 2048 << 10;
    objects[2].packedEntity = 2049 << 10;
    objectIndices[17] = 0;
    objectIndices[2048] = 1;
    objectIndices[2049] = 2;
    AK_SceneModels[0].packedEntity = 18 << 10;
    AK_SceneModels[1].packedEntity = 2048 << 10;
    modelIndices[18] = 0;
    modelIndices[2048] = 1;
    AK_SceneObjectCount = 3;
    AK_SceneModelCount = 2;
    AK_SceneObjectModelCount = 1;
    AK_SceneBrushCount = 0;
    AK_SceneEntityCount = 4;
    AK_ViewCount = 0;
    AK_FirstClient = local;
    AK_Backend = backends[0];
    streamingUpdates = 0;
    streamingWaits = 0;
    s_objectStreaming = {};
    interpolations = cameraUpdates = extraRenders = disarms = 0;
    trace.clear();
    failObject = failKiller = capturedMain = capturedObject = pip = false;
    mainThread = true;
    supportsGraph = true;
    gameMode = 2;
    expectCameraCut = true;
    retainedStamps = 0;
    thirdPersonReturn = 1;
    option.current.integer = 1;
}

int main()
{
    mainThread = false;
    DW_AltKillcam_Init();
    REQUIRE(registrations == 0);
    mainThread = true;
    DW_AltKillcam_Init();
    DW_AltKillcam_Init();
    REQUIRE(registrations == 1 && begins == 1 && ends == 1 && option.current.integer == 0);
    ++cases;
    for (int l = 0; l < 2; ++l)
        for (int type = 1; type <= 9; ++type)
            for (unsigned draw = 1; draw <= 3; ++draw)
            {
                Reset(l, type);
                DW_AltKillcam_Predict(l);
                DW_AltKillcam_CalcView(l);
                DW_AltKillcam_WeaponAnim(l);
                DW_AltKillcam_AddViewWeapon(l);
                REQUIRE(DW_AltKillcam_UpdateThirdPerson(l) == 1);
                REQUIRE(!OwnerView(l) && Field<int32_t>(globals[l], 533724) == type);
                for (int stage = 0; stage < 5; ++stage)
                    REQUIRE(!insideEntity[stage] && !insideFov[stage]);
                DW_AltKillcam_LerpView(l);
                REQUIRE(interpolations == 1 && cameraUpdates == 1);
                REQUIRE(Origin(Ref(l)) == 100 + l);
                const DWAltKillcamThirdPersonState expectedThirdPerson{0, 0x12344321U, 0, 0};
                REQUIRE(!std::memcmp(globals[l] + 311392, &expectedThirdPerson, 16));
                DW_AltKillcam_RenderScene(l, Ref(l), draw);
                REQUIRE(extraRenders == 2 && capturedMain && capturedObject && AK_ViewCount == 2);
                REQUIRE(streamingUpdates == 1 && !s_objectStreaming.active);
                REQUIRE(streamingWaits == 1);
                REQUIRE(interpolations == 1 && originalCounts[5] == 0 && !s_busy);
                for (int stage = 0; stage < 4; ++stage)
                    REQUIRE(originalCounts[stage] == 1);
                REQUIRE(originalCounts[6] == 1);
                REQUIRE(trace == "NOVMXLREDCBVMXLNKR");
                REQUIRE(Ref(l)->unknown3228 == 0x87654321 && Ref(l)->time == 777);
                REQUIRE(stampedInset.x == l * 1920 + 1920 - 480 - 96 &&
                        stampedInset.y == 1080 / 5 && stampedInset.width == 480 &&
                        stampedInset.height == 270);
                REQUIRE(Ref(l)->playerTeleported == 0);
                ++cases;
            }
    for (int mismatch = 0; mismatch < 8; ++mismatch)
    {
        Reset();
        Camera camera;
        REQUIRE(GetCamera(0, &camera));
        DWAltKillcamSceneView view{};
        view.backend = AK_Backend;
        view.localClient = 0;
        view.viewIndex = Field<int32_t>(camera.globals, 167080);
        {
            ObjectStreamingScope scope(camera);
            switch (mismatch)
            {
            case 0:
                break;
            case 1:
                mainThread = false;
                break;
            case 2:
                view.backend = backends[1];
                break;
            case 3:
                ++view.viewIndex;
                break;
            case 4:
                view.localClient = 1;
                break;
            case 5:
                ++Field<int32_t>(AK_Backend, 33256);
                break;
            case 6:
                AK_Backend = backends[1];
                break;
            case 7:
                break;
            }
            DW_AltKillcam_UpdateStreaming(mismatch == 7 ? nullptr : &view);
            REQUIRE(streamingUpdates == (mismatch == 0 ? 0 : 1));
            REQUIRE(streamingWaits == (mismatch == 0 ? 1 : 0));
        }
        REQUIRE(!s_objectStreaming.active);
        mainThread = true;
        DW_AltKillcam_UpdateStreaming(&view);
        REQUIRE(streamingUpdates == (mismatch == 0 ? 1 : 2));
        ++cases;
    }
    for (int invalid = 0; invalid < 17; ++invalid)
    {
        Reset();
        DW_AltKillcam_LerpView(0);
        switch (invalid)
        {
        case 0:
            option.current.integer = 0;
            break;
        case 1:
            Field<int32_t>(globals[0], 533720) = 0;
            break;
        case 2:
            Field<int32_t>(globals[0], 533724) = 0;
            break;
        case 3:
            Field<int32_t>(globals[0], 12064) = 0;
            break;
        case 4:
            Field<void *>(globals[0], 26000) = nullptr;
            break;
        case 5:
            Field<int32_t>(snapshots[0], 488) = 99;
            break;
        case 6:
            Field<int32_t>(globals[0], 533740) = 2047;
            break;
        case 7:
            Field<int32_t>(globals[0], 26020) = 1001;
            break;
        case 8:
            AK_ViewCount = 5;
            break;
        case 9:
            AK_SceneObjectCount = 513;
            break;
        case 10:
            AK_SceneObjectModelCount = 3;
            break;
        case 11:
            Ref(0)->displayViewport[2] = 63;
            break;
        case 12:
            mainThread = false;
            break;
        case 13:
            AK_EntitySystems[0] = nullptr;
            break;
        case 14:
            gameMode = 0;
            break;
        case 15:
            gameMode = 1;
            break;
        case 16:
            gameMode = 3;
            break;
        }
        expectCameraCut = invalid == 2 || invalid == 6 || invalid == 13;
        DW_AltKillcam_RenderScene(0, Ref(0), 3);
        if (invalid == 2 || invalid == 6 || invalid == 13)
        {
            // A valid pose sampled before destruction can render the current
            // scene even if the object disappears before its first capture.
            REQUIRE(originalCounts[5] == 0 && extraRenders == 2 && capturedMain &&
                    capturedObject && retainedStamps == 0 && AK_ViewCount == 2);
        }
        else
            REQUIRE(originalCounts[5] == 1 && extraRenders == 0);
        REQUIRE(interpolations == 1 && !s_busy);
        ++cases;
    }
    Reset();
    DW_AltKillcam_LerpView(0);
    failObject = true;
    expectCameraCut = false;
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(extraRenders == 1 && !capturedMain && capturedObject && interpolations == 1);
    ++cases;
    Reset();
    DW_AltKillcam_LerpView(0);
    failKiller = true;
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(extraRenders == 2 && disarms == 1 && !s_busy);
    ++cases;
    Reset();
    option.current.integer = 0;
    DW_AltKillcam_Predict(0);
    DW_AltKillcam_CalcView(0);
    DW_AltKillcam_WeaponAnim(0);
    DW_AltKillcam_AddViewWeapon(0);
    REQUIRE(DW_AltKillcam_UpdateThirdPerson(0) == 1);
    DW_AltKillcam_LerpView(0);
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(originalCounts[0] == 1 && originalCounts[1] == 1 && originalCounts[2] == 1 &&
            originalCounts[3] == 1 && originalCounts[6] == 1);
    for (int stage = 0; stage < 5; ++stage)
        REQUIRE(insideEntity[stage] && insideFov[stage]);
    REQUIRE(originalCounts[4] == 1 && originalCounts[5] == 1 && cameraUpdates == 0 &&
            extraRenders == 0 && disarms == 0);
    ++cases;
    Reset();
    DW_AltKillcam_LerpView(0);
    DW_AltKillcam_LerpView(1);
    DW_AltKillcam_RenderScene(0, Ref(0), 1);
    AK_FirstClient = 1;
    DW_AltKillcam_RenderScene(1, Ref(1), 2);
    REQUIRE(extraRenders == 4 && interpolations == 2 && AK_ViewCount == 4);
    ++cases;
    Reset();
    Field<int32_t>(globals[0], 12064) = -50;
    DW_AltKillcam_LerpView(0);
    AK_ViewCount = 4;
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(extraRenders == 2 && AK_ViewCount == 6);
    option.current.integer = 0;
    DW_AltKillcam_LerpView(0);
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(disarms == 1 && originalCounts[5] == 1 && !s_renderArmed[0]);
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(disarms == 1 && originalCounts[5] == 2);
    ++cases;
    Reset();
    supportsGraph = false;
    DW_AltKillcam_Predict(0);
    DW_AltKillcam_CalcView(0);
    DW_AltKillcam_LerpView(0);
    DW_AltKillcam_RenderScene(0, Ref(0), 3);
    REQUIRE(cameraUpdates == 0 && interpolations == 1 && originalCounts[5] == 1 &&
            extraRenders == 0);
    ++cases;
    int thirdPersonCases = 0, continuationCases = 0, replayBoundaryCases = 0;
    int uncapturedCases = 0;
    int cameraCutCases = 0, insetCases = 0;
    for (int enabled = 0; enabled < 2; ++enabled)
        for (uint32_t result = 0; result < 2; ++result)
        {
            Reset();
            option.current.integer = enabled;
            thirdPersonReturn = result;
            REQUIRE(DW_AltKillcam_UpdateThirdPerson(0) == result);
            REQUIRE(originalCounts[6] == 1 && !OwnerView(0));
            REQUIRE(insideEntity[4] == !enabled && insideFov[4] == !enabled);
            ++thirdPersonCases;
            ++cases;
        }
    for (unsigned l = 0; l < 2; ++l)
        for (int loss = 0; loss < 4; ++loss)
        {
            Reset(l);
            DW_AltKillcam_LerpView(l);
            DW_AltKillcam_RenderScene(l, Ref(l), 3);
            const uint64_t token = s_replay[l].lastObjectToken;
            REQUIRE(token && s_replay[l].active);
            switch (loss)
            {
            case 0: Field<int32_t>(globals[l], 533724) = 0; break;
            case 1: Field<uint8_t>(entities[l], 752 * 17 + 640) = 0; break;
            case 2: AK_EntitySystems[l] = nullptr; break;
            case 3: Field<int32_t>(globals[l], 533740) = 2047; break;
            }
            ++Field<int32_t>(globals[l], 26020);
            Ref(l)->time = 888;
            Ref(l)->unknown3228 = 0x10203040;
            Ref(l)->displayViewport[2] = 1280;
            Ref(l)->displayViewport[3] = 720;
            objects[0].unknown0[0] = 41;
            DW_AltKillcam_Predict(l);
            REQUIRE(!insideEntity[0] && !insideFov[0] && !OwnerView(l));
            DW_AltKillcam_LerpView(l);
            REQUIRE(interpolations == 2 && cameraUpdates == 1 && !s_objectCamera[l].valid);
            REQUIRE(Origin(Ref(l)) == 100 + l);
            const DWAltKillcamThirdPersonState expected{0, 0x12344321U, 0, 0};
            REQUIRE(!std::memcmp(globals[l] + 311392, &expected, sizeof(expected)));
            trace.clear(); AK_ViewCount = 0; AK_Backend = backends[0];
            expectCameraCut = true; capturedMain = capturedObject = false;
            DW_AltKillcam_RenderScene(l, Ref(l), 3);
            REQUIRE(trace == "NOVMXLREDCBVMXLNKR" && extraRenders == 4 && AK_ViewCount == 2);
            REQUIRE(capturedMain && capturedObject && retainedStamps == 0);
            REQUIRE(streamingUpdates == 2 && streamingWaits == 2);
            REQUIRE(s_replay[l].lastObjectToken > token && !s_busy && disarms == 0);
            REQUIRE(submittedObjectTime == 888 && submittedObjectFrameTag == 0x10203040);
            REQUIRE(submittedObjectSceneTag == 41);
            REQUIRE(!std::memcmp(submittedObjectViewport, Ref(l)->displayViewport,
                                 sizeof(submittedObjectViewport)));
            REQUIRE(Ref(l)->playerTeleported == 0);
            const uint64_t continuedToken = s_replay[l].lastObjectToken;
            ++Field<int32_t>(globals[l], 26020);
            Ref(l)->time = 999;
            Ref(l)->unknown3228 = 0x50607080;
            objects[0].unknown0[0] = 42;
            DW_AltKillcam_LerpView(l);
            trace.clear(); AK_ViewCount = 0; AK_Backend = backends[0];
            DW_AltKillcam_RenderScene(l, Ref(l), 3);
            REQUIRE(extraRenders == 6 && s_replay[l].lastObjectToken > continuedToken);
            REQUIRE(submittedObjectTime == 999 && submittedObjectFrameTag == 0x50607080);
            REQUIRE(submittedObjectSceneTag == 42 && retainedStamps == 0);
            REQUIRE(interpolations == 3 && cameraUpdates == 1);
            REQUIRE(streamingUpdates == 3 && streamingWaits == 3);
            ++continuationCases;
            ++cases;
        }
    for (unsigned l = 0; l < 2; ++l)
    {
        Reset(l);
        DW_AltKillcam_LerpView(l);
        DW_AltKillcam_RenderScene(l, Ref(l), 3);
        const uint64_t token = s_replay[l].lastObjectToken;
        Field<int32_t>(globals[l], 533724) = 0;
        DW_AltKillcam_LerpView(l);
        Ref(l)->playerTeleported = 1;
        expectCameraCut = true; failKiller = true;
        trace.clear(); AK_ViewCount = 0; AK_Backend = backends[0];
        DW_AltKillcam_RenderScene(l, Ref(l), 3);
        REQUIRE(trace == "NOVMXLREDCBVMXLNKR" && retainedStamps == 0 && extraRenders == 4);
        REQUIRE(disarms == 1 && !s_renderArmed[l] && s_replay[l].lastObjectToken > token);
        REQUIRE(Ref(l)->playerTeleported == 1 && interpolations == 2 && cameraUpdates == 1);
        REQUIRE(!s_busy && !s_objectStreaming.active);
        ++continuationCases;
        ++cases;
    }
    for (unsigned l = 0; l < 2; ++l)
    {
        Reset(l);
        DW_AltKillcam_Predict(l);
        REQUIRE(s_replay[l].active && !s_replay[l].hasObjectPose);
        Field<int32_t>(globals[l], 533724) = 0;
        DW_AltKillcam_LerpView(l);
        expectCameraCut = false;
        DW_AltKillcam_RenderScene(l, Ref(l), 3);
        REQUIRE(trace == "NR" && extraRenders == 1 && capturedMain && !capturedObject);
        REQUIRE(!s_replay[l].lastObjectToken && retainedStamps == 0 && cameraUpdates == 0);
        REQUIRE(streamingUpdates == 1 && streamingWaits == 0 && !s_busy);
        ++uncapturedCases;
        ++cases;
    }
    for (unsigned l = 0; l < 2; ++l)
        for (int boundary = 0; boundary < 8; ++boundary)
        {
            Reset(l);
            DW_AltKillcam_LerpView(l);
            DW_AltKillcam_RenderScene(l, Ref(l), 3);
            REQUIRE(s_replay[l].lastObjectToken);
            Field<int32_t>(globals[l], 533724) = 0;
            switch (boundary)
            {
            case 0: Field<int32_t>(globals[l], 533720) = 0; break;
            case 1: ++Field<int32_t>(globals[l], 533728); break;
            case 2:
                ++Field<int32_t>(globals[l], 456);
                ++Field<int32_t>(snapshots[l], 488);
                break;
            case 3:
                std::memcpy(replacementGlobals, globals[l], sizeof(replacementGlobals));
                AK_CgGlobals[l] = replacementGlobals;
                break;
            case 4: Field<int32_t>(globals[l], 533724) = 10; break;
            case 5: option.current.integer = 0; break;
            case 6: supportsGraph = false; break;
            case 7: gameMode = 1; break;
            }
            Camera c;
            REQUIRE(!GetCamera(l, &c));
            REQUIRE(!s_replay[l].active && !s_replay[l].lastObjectToken &&
                    !s_replay[l].hasObjectPose && !s_objectCamera[l].valid &&
                    !s_renderArmed[l] && disarms == 1);
            REQUIRE(!GetCamera(l, &c) && disarms == 1);
            option.current.integer = 1; supportsGraph = true; gameMode = 2;
            Field<int32_t>(AK_CgGlobals[l], 533720) = 1;
            Field<int32_t>(AK_CgGlobals[l], 533724) = 3;
            REQUIRE(GetCamera(l, &c) && s_replay[l].active && !s_replay[l].lastObjectToken &&
                    !s_replay[l].hasObjectPose);
            ++replayBoundaryCases;
            ++cases;
        }
    for (unsigned l = 0; l < 2; ++l)
        for (int cut = 0; cut < 2; ++cut)
            for (int failure = 0; failure < 3; ++failure)
            {
                Reset(l);
                Ref(l)->playerTeleported = static_cast<uint8_t>(cut);
                DW_AltKillcam_LerpView(l);
                failObject = failure == 1; failKiller = failure == 2;
                expectCameraCut = failure == 1 ? bool(cut) : true;
                DW_AltKillcam_RenderScene(l, Ref(l), 3);
                REQUIRE(Ref(l)->playerTeleported == cut);
                REQUIRE(extraRenders == (failure == 1 ? 1 : 2) && interpolations == 1);
                REQUIRE(disarms == (failure == 2 ? 1 : 0) && !s_busy);
                ++cameraCutCases;
                ++cases;
            }
    for (unsigned l = 0; l < 2; ++l)
        for (int size = 0; size < 3; ++size)
        {
            Reset(l);
            const int widths[]{1920, 2560, 1365}, heights[]{1080, 1440, 767};
            Ref(l)->displayViewport[0] = 100 + 2000 * static_cast<int>(l);
            Ref(l)->displayViewport[1] = 37;
            Ref(l)->displayViewport[2] = widths[size];
            Ref(l)->displayViewport[3] = heights[size];
            DW_AltKillcam_LerpView(l);
            DW_AltKillcam_RenderScene(l, Ref(l), 2);
            REQUIRE(stampedInset.width == widths[size] / 4 && stampedInset.height == heights[size] / 4);
            REQUIRE(stampedInset.x == Ref(l)->displayViewport[0] + widths[size] - widths[size] / 4 - widths[size] / 20);
            REQUIRE(stampedInset.y == 37 + heights[size] / 5);
            ++insetCases;
            ++cases;
        }
    for (int i = 0; i < 100; ++i)
    {
        Reset();
        DWAltKillcamRefdef copy;
        SetOrigin(Ref(0), static_cast<float>(i));
        CopyCamera(&copy, Ref(0));
        REQUIRE(Origin(&copy) == static_cast<float>(i) && copy.unknown3228 == Ref(0)->unknown3228);
        CopyCamera(Ref(0), &copy);
        for (int component = 0; component < 3; ++component)
            REQUIRE(Origin(Ref(0), component) == static_cast<float>(i + component * 17));
        ++cases;
    }
    for (unsigned l = 0; l < 2; ++l)
        for (int active = 0; active < 2; ++active)
            for (int type = 0; type < 12; ++type)
            {
                Reset(l, type);
                option.current.integer = 0;
                Field<int32_t>(globals[l], 533720) = active;
                std::printf("PRED %u %d %d %d %d\n",
                            l,
                            active,
                            type,
                            DW_AltKillcam_EntityView(l),
                            DW_AltKillcam_EntityFov(l));
            }
    for (unsigned l = 0; l < 2; ++l)
        for (int first = 0; first < 2; ++first)
            for (int flag = 0; flag < 2; ++flag)
                for (int p = 0; p < 2; ++p)
                    for (unsigned draw = 1; draw <= 3; ++draw)
                    {
                        Reset(l);
                        AK_FirstClient = first;
                        pip = p;
                        Field<uint8_t>(globals[l], 168533) = static_cast<uint8_t>(flag);
                        Camera c;
                        REQUIRE(GetCamera(l, &c));
                        ReserveView(c);
                        expectCameraCut = false;
                        RenderReserved(c, draw, 0);
                        std::printf("SUBMIT %u %d %d %d %u ", l, first, flag, p, draw);
                        for (const auto byte :
                             *reinterpret_cast<const uint8_t (*)[48]>(&submittedFeatures))
                            std::printf("%02x", byte);
                        std::printf("\n");
                    }
    std::printf("{\"cases\":%d,\"active_pair_cases\":54,\"failure_cases\":19,\"origin_cases\":100,"
                "\"streaming_scope_cases\":8,\"third_person_cases\":%d,\"continuation_cases\":%d,"
                "\"uncaptured_cases\":%d,"
                "\"replay_boundary_cases\":%d,\"camera_cut_cases\":%d,\"inset_cases\":%d}\n",
                cases, thirdPersonCases, continuationCases, uncapturedCases,
                replayBoundaryCases, cameraCutCases, insetCases);
}
