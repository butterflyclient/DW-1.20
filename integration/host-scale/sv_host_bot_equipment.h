#pragma once
#include "sv_host_scale.h"

namespace HostScale
{
    // Replay 1.20 views verified against Bot_Weap_Update, BG_EquipWeapon,
    // SV_BotSwitchWeapon and the native client script-field table.
    struct BotWeapon
    {
        uint16_t index;
        uint8_t configuration[58];
    };

#pragma pack(push, 2)

    struct BotWeaponEntry
    {
        uint16_t mapIndex;
        BotWeapon weapon;
    };

#pragma pack(pop)

    struct BotWeaponMap
    {
        const uintptr_t *vtable;
        BotWeaponEntry *entries;
    };

#pragma pack(push, 4)

    struct BotEquipmentPlayer
    {
        uint8_t opaque0[12];
        int32_t movementType, movementTime;
        uint64_t movementFlags;
        uint8_t opaque28[1424];
        uint32_t inventory[15];
        uint8_t opaque1512[272];
        uint32_t currentWeapon;
        uint8_t opaque1788[8];
        uint64_t weaponFlags;
        uint8_t opaque1804[20532];
        uint32_t gameExtraInfo;
    };

#pragma pack(pop)

    struct BotEquipmentData
    {
        Entity *entity;
        Sentient *sentient;
        uint8_t opaque16[432];
        BotEquipmentPlayer *player;
        const UserCmd *lastCommand;
        uint8_t opaque464[8520];
        uint32_t scriptFlags, scriptButtons;
        uint8_t opaque8992[18812];
        BotWeapon scriptWeapon;
    };

    static_assert(sizeof(BotWeapon) == 60 && sizeof(BotWeaponEntry) == 62);
    static_assert(offsetof(BotWeaponMap, entries) == 8);
    static_assert(offsetof(BotEquipmentPlayer, inventory) == 1452);
    static_assert(offsetof(BotEquipmentPlayer, currentWeapon) == 1784);
    static_assert(offsetof(BotEquipmentPlayer, weaponFlags) == 1796);
    static_assert(offsetof(BotEquipmentPlayer, gameExtraInfo) == 22336);
    static_assert(offsetof(BotEquipmentData, player) == 448);
    static_assert(offsetof(BotEquipmentData, lastCommand) == 456);
    static_assert(offsetof(BotEquipmentData, scriptFlags) == 8984);
    static_assert(offsetof(BotEquipmentData, scriptWeapon) == 27804);
} // namespace HostScale

extern "C"
{
    bool SV_HostBot_PrepareEquipment(void *);
    bool SV_HostBot_NeedsRangedWeapon(void *);
    bool SV_HostBot_InGulag(void *);
}
