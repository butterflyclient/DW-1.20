#pragma once
#include <stdint.h>
#include <stddef.h>

// Target Replay prefixes only. Unknown fields retain their native storage;
// no later-build playerState, weapon package or XAnim enum is substituted.
struct DWInspectWeapon
{
    uint16_t index;
    uint8_t remaining[58];
};
static_assert(sizeof(DWInspectWeapon) == 60);

struct DWInspectUserCmd
{
    uint64_t buttons;
    uint32_t unknown8;
    int32_t serverTime;
    uint8_t unknown16[20];
    DWInspectWeapon weapon;
    uint8_t remaining96[168];
};
static_assert(sizeof(DWInspectUserCmd) == 264);
static_assert(offsetof(DWInspectUserCmd, serverTime) == 12);
static_assert(offsetof(DWInspectUserCmd, weapon) == 36);

struct DWInspectWeaponHand
{
    uint32_t unknown0;
    int32_t previousAnimation;
    int32_t animation;
    uint8_t unknown12[12];
    int32_t weaponTime;
    int32_t weaponDelay;
    uint8_t unknown32[8];
    int32_t state;
    uint8_t unknown44[36];
};
static_assert(sizeof(DWInspectWeaponHand) == 80);
static_assert(offsetof(DWInspectWeaponHand, weaponTime) == 24);
static_assert(offsetof(DWInspectWeaponHand, weaponDelay) == 28);
static_assert(offsetof(DWInspectWeaponHand, state) == 40);

struct DWInspectPlayerState
{
    uint8_t unknown0[12];
    int32_t movementType;
    uint8_t unknown16[4];
    uint32_t movementFlags[2];
    uint32_t otherFlags[2];
    uint8_t unknown36[412];
    int32_t clientNumber;
    uint8_t unknown452[800];
    uint32_t scriptAnimation;
    int32_t scriptStartTime;
    uint8_t unknown1260[28];
    DWInspectWeaponHand hands[2];
    uint8_t unknown1448[348];
    uint32_t weaponFlags[2];
    float adsFraction;
};
static_assert(sizeof(DWInspectPlayerState) == 1808);
static_assert(offsetof(DWInspectPlayerState, movementFlags) == 20);
static_assert(offsetof(DWInspectPlayerState, otherFlags) == 28);
static_assert(offsetof(DWInspectPlayerState, clientNumber) == 448);
static_assert(offsetof(DWInspectPlayerState, scriptAnimation) == 1252);
static_assert(offsetof(DWInspectPlayerState, scriptStartTime) == 1256);
static_assert(offsetof(DWInspectPlayerState, hands) == 1288);
static_assert(offsetof(DWInspectPlayerState, weaponFlags) == 1796);
static_assert(offsetof(DWInspectPlayerState, adsFraction) == 1804);

struct DWInspectPmove
{
    void *vtable;
    DWInspectPlayerState *ps;
    DWInspectUserCmd command;
    DWInspectUserCmd previousCommand;
    uint8_t unknown544[296];
    void *handler;
    uint8_t unknown848[48];
    void *weaponMap;
};
static_assert(sizeof(DWInspectPmove) == 904);
static_assert(offsetof(DWInspectPmove, command) == 16);
static_assert(offsetof(DWInspectPmove, previousCommand) == 280);
static_assert(offsetof(DWInspectPmove, handler) == 840);
static_assert(offsetof(DWInspectPmove, weaponMap) == 896);

struct DWInspectAnimationPackage
{
    const char *name;
};
struct DWInspectWeaponDefinition
{
    uint8_t unknown0[144];
    const DWInspectAnimationPackage *primaryAnimationPackage;
};
static_assert(offsetof(DWInspectWeaponDefinition, primaryAnimationPackage) == 144);

extern "C" {
void DW_WeaponInspect_Request(uint32_t localClient);
// Called only after native reliable-command sender/entity/living validation.
void DW_WeaponInspect_ServerRequest(int32_t clientNumber, void *playerState);
uint8_t DW_WeaponInspect_PMove(DWInspectPmove *pmove, void *pml);
uint8_t DW_WeaponInspect_UpdateSprint(DWInspectPmove *pmove, void *pml);
// Retained identity is also needed during the native outgoing animation blend.
bool DW_WeaponInspect_HasClip(const DWInspectPlayerState *playerState);
bool DW_WeaponInspect_IsActive(const DWInspectPlayerState *playerState);
}
