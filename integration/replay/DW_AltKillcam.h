#pragma once

#include <stddef.h>
#include <stdint.h>

// Entire Replay camera records are carried between the two native scenes.
// Unknown fields remain opaque instead of borrowing a newer engine layout.
struct DWAltKillcamRefdefView
{
    float tanHalfFovX, tanHalfFovY;
    uint32_t encodedOrigin[3];
    float axis[3][3];
    uint32_t unknown56;
    uint32_t unknown60[10];
    uint32_t originKey, originSeed;
};

struct DWAltKillcamRefdef
{
    int32_t displayViewport[4];
    DWAltKillcamRefdefView view;
    float viewOffset[3], previousViewOffset[3];
    int32_t time;
    uint8_t unknown152[704];
    uint8_t playerTeleported, unknown857[3];
    int32_t localClientNum;
    uint8_t unknown864[2360];
    uint32_t unknown3224, unknown3228;
};

struct DWAltKillcamSceneDObj
{
    uint8_t unknown0[1648];
    uint32_t packedEntity;
    uint32_t renderFlags;
    void *object;
    uint8_t unknown1664[24];
};

struct DWAltKillcamSceneModel
{
    uint8_t unknown0[120];
    uint32_t packedEntity;
    uint32_t renderFlags;
    uint8_t unknown128[24];
};

struct DWAltKillcamSceneBrush
{
    uint8_t native[88];
};

struct DWAltKillcamFeatures
{
    int32_t viewportType;
    uint8_t unknown4[36];
    uint32_t flags40, flags44;
};

// Complete Replay streaming view records. This target stores one client's
// eight views in each of two saved buffers, not the newer two-client layout.
struct DWAltKillcamStreamMultiView
{
    float positions[8][4], directions[8][4], velocityDirections[8][4];
    float zoom[8], velocityZoom[8], cosFov[8], distanceScaleSquared[8];
    uint32_t viewTag[8], count;
};

struct DWAltKillcamSavedStreamViews
{
    uint32_t currentBuffer, count[2];
    float positions[2][8][3], directions[2][8][3], velocities[2][8][3];
    float zoom[2][8], cosFov[2][8];
    uint32_t viewTag[2][8];
};

struct DWAltKillcamSceneView
{
    uint8_t unknown0[11592];
    void *backend;
    int32_t viewIndex, localClient;
    uint8_t unknown11608[12120];
};

struct DWAltKillcamThirdPersonState
{
    int32_t spectatingThirdPerson;
    uint32_t unknown396;
    int32_t renderingThirdPerson, activeCameraEnabledThirdPerson;
};

struct DWAltKillcamNativeState
{
    int32_t active, objectType, startTime;
    uint32_t unknown12;
    uint8_t entityOriginValid, unknown17[3];
    int32_t entity;
    uint8_t unknown24[112];
    float entityOrigin[3];
    uint32_t unknown148[2];
    int32_t transitionEndTime;
    float previousAngles[3], previousOrigin[3];
};

static_assert(sizeof(DWAltKillcamRefdefView) == 108);
static_assert(sizeof(DWAltKillcamRefdef) == 3232);
static_assert(offsetof(DWAltKillcamRefdef, view) == 16);
static_assert(offsetof(DWAltKillcamRefdef, viewOffset) == 124);
static_assert(offsetof(DWAltKillcamRefdef, time) == 148);
static_assert(offsetof(DWAltKillcamRefdef, playerTeleported) == 856);
static_assert(offsetof(DWAltKillcamRefdef, localClientNum) == 860);
static_assert(sizeof(DWAltKillcamSceneDObj) == 1688);
static_assert(offsetof(DWAltKillcamSceneDObj, object) == 1656);
static_assert(sizeof(DWAltKillcamSceneModel) == 152);
static_assert(sizeof(DWAltKillcamSceneBrush) == 88);
static_assert(sizeof(DWAltKillcamFeatures) == 48);
static_assert(sizeof(DWAltKillcamStreamMultiView) == 548);
static_assert(offsetof(DWAltKillcamStreamMultiView, count) == 544);
static_assert(sizeof(DWAltKillcamSavedStreamViews) == 780);
static_assert(offsetof(DWAltKillcamSavedStreamViews, positions) == 12);
static_assert(offsetof(DWAltKillcamSavedStreamViews, zoom) == 588);
static_assert(sizeof(DWAltKillcamSceneView) == 23728);
static_assert(offsetof(DWAltKillcamSceneView, backend) == 11592);
static_assert(sizeof(DWAltKillcamThirdPersonState) == 16);
static_assert(offsetof(DWAltKillcamThirdPersonState, renderingThirdPerson) == 8);
static_assert(sizeof(DWAltKillcamNativeState) == 184);
static_assert(offsetof(DWAltKillcamNativeState, entity) == 20);
static_assert(offsetof(DWAltKillcamNativeState, transitionEndTime) == 156);

extern "C" void DW_AltKillcam_Init();
