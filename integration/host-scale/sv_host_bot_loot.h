#pragma once
#include "sv_host_scale.h"

namespace HostScale
{
    // Script-owned BR circles, copied on the server thread. No VM/nav pointers.
    struct BotGasState
    {
        Vec3 currentCenter, nextCenter;
        float currentRadius, nextRadius;
        int32_t sampledTime;
        uint32_t generation;
        bool closing, valid;
    };
    struct LootUsableRef
    {
        uint32_t index;
        uint16_t opaque4;
        uint8_t useClass, part;
    };

    struct LootUsableItem
    {
        LootUsableRef reference;
        int32_t priority;
        float score;
        uint8_t flags, inDisplayDistance, inDisplayFov, ignored;
    };

    struct LootUsableList
    {
        LootUsableItem items[1000];
        uint16_t count, ignoredCount;
    };

    // Replay BG_SpawnGroup_Loot_ItemDef is a 256-byte table row. ParseItemDef
    // writes these fields; only the verified identity prefix is consumed here.
    struct LootItemDefinition
    {
        const void *scriptableDefinition;
        const char *name;
        int32_t quantity;
        uint8_t type, opaque21;
        uint16_t rarity;
        uint8_t opaque24[232];
    };

    struct BotLootLookRequest
    {
        Vec3 point;
        int32_t endTime;
        uint32_t opaque16;
        int32_t type;
    };

    static_assert(sizeof(LootUsableRef) == 8 && sizeof(LootUsableItem) == 20);
    static_assert(offsetof(LootUsableItem, flags) == 16);
    static_assert(offsetof(LootUsableItem, inDisplayDistance) == 17);
    static_assert(sizeof(LootUsableList) == 20004 && offsetof(LootUsableList, count) == 20000);
    static_assert(sizeof(LootItemDefinition) == 256);
    static_assert(offsetof(LootItemDefinition, name) == 8);
    static_assert(offsetof(LootItemDefinition, type) == 20);
    static_assert(offsetof(LootItemDefinition, rarity) == 22);
    static_assert(sizeof(BotLootLookRequest) == 24);
    static_assert(offsetof(BotLootLookRequest, type) == 20);
} // namespace HostScale

extern "C"
{
    void SV_HostBot_ResetGasState();
    bool SV_HostBot_PublishGasState(const HostScale::BotGasState *);
    bool SV_HostBot_GetGasState(HostScale::BotGasState *);
    bool SV_HostBot_GasEvacuationRequired(void *);
    // Stable value-only destination. The caller must project it onto the real
    // native mesh and install a successful native route before following it.
    bool SV_HostBot_GetGasGoal(void *, HostScale::Vec3 *);
    // Main server thread, after a full BotThink and before movement workers.
    void SV_HostBot_UpdateLoot(void *, HostScale::UserCmd *);
    // Nearby native usable position for the ordinary navigator/look controller.
    // No Scriptable, definition or navigation pointer is retained as a goal.
    bool SV_HostBot_GetLootGoal(void *, HostScale::Vec3 *);
    // Native look request + native command encoding. The temporary request is
    // restored after the call; combat/script look priorities remain authoritative.
    bool SV_HostBot_FaceLoot(void *, HostScale::UserCmd *);
    bool SV_HostBot_AllowSurvival(void *);
    bool SV_HostBot_NeedsRangedWeapon(void *);
}
