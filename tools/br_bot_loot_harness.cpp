#define SVHBL_TESTING 1
#include "../integration/host-scale/SV_HostBot_Loot.cpp"

namespace
{
    bool enabled = true, needsWeapon = true, firing, skydiving;
    void *tlsValue = reinterpret_cast<void *>(0x1111);
    void **SVHBL_TestGameStaticsSlot() { return &tlsValue; }
    LootUsableList provided{};
    LootItemDefinition definitions[16]{};
    Vec3 positions[16]{};
    uint32_t generations[16]{};
    bool inUse[16]{};
    unsigned scans, uses, usedIndex, usedGeneration;
    unsigned lookRequests, directionUpdates;
    bool usedAuto;
    Entity entity{};
    Sentient sentient{};
    uint8_t client[65536]{}, player[2048]{};
    BotLootView bot{};
    UserCmd command{};
    void Setup()
    {
        entity.client = client;
        entity.sentient = &sentient;
        entity.health = 100;
        bot.entity = &entity;
        bot.sentient = &sentient;
        bot.playerState = player;
        Field<int32_t>(player, 0) = 10000;
        Field<int32_t>(player, 4) = 0;
        Field<uint16_t>(player, 626) = 0;
        for (unsigned i = 0; i < 16; ++i)
        {
            inUse[i] = true;
            generations[i] = 3;
            positions[i] = {32, 0, 16};
        }
    }
    void Candidate(unsigned row, unsigned index, const char *name, uint8_t flags)
    {
        definitions[index].name = name;
        provided.items[row] = {{index, 0, 1, 2}, 0, 0, flags, 1, 1, 0};
        if (row >= provided.count) provided.count = uint16_t(row + 1);
    }
}
namespace HostScale { bool Enabled() { return enabled; } }
extern "C"
{
    int _fltused = 0;
    int32_t SVHS_LevelTime = 1000;
    void *SVHS_GameStatics = reinterpret_cast<void *>(0x2222);
    bool SVHS_BotCanFire(void *) { return firing; }
    bool SV_HostBot_NeedsRangedWeapon(void *) { return needsWeapon; }
    int SVHBL_GetUseList(Entity *, LootUsableList *out, int)
    {
        ++scans;
        if (tlsValue != SVHS_GameStatics) return 0;
        *out = provided;
        return out->count;
    }
    void SVHBL_UseScriptable(const Entity *, unsigned index, uint8_t part, unsigned generation, bool autoUse)
    {
        if (part != 2 || tlsValue != SVHS_GameStatics) return;
        ++uses;
        usedIndex = index;
        usedGeneration = generation;
        usedAuto = autoUse;
    }
    const LootItemDefinition *SVHBL_LootDefinition(unsigned index) { return &definitions[index]; }
    const void *SVHBL_LootTable() { return reinterpret_cast<void *>(1); }
    unsigned SVHBL_UseCount(unsigned index) { return generations[index]; }
    bool SVHBL_InstanceInUse(unsigned index) { return index < 16 && inUse[index]; }
    bool SVHBL_IsSkydiving(const void *) { return skydiving; }
    void SVHBL_UsePosition(const LootUsableRef *ref, Vec3 *out) { *out = positions[ref->index]; }
    void SVHBL_LookAtPoint(void *data, const Vec3 *point, int duration, int type)
    {
        auto *view = static_cast<BotLootView *>(data);
        if (tlsValue != SVHS_GameStatics) return;
        ++lookRequests;
        view->look.point = *point;
        view->look.endTime = SVHS_LevelTime + duration;
        view->look.type = type;
    }
    void SVHBL_UpdateDirection(void *data, UserCmd *out)
    {
        auto *view = static_cast<BotLootView *>(data);
        if (tlsValue == SVHS_GameStatics && view->look.type == 3 &&
            view->look.point.x == 32 && view->look.endTime > SVHS_LevelTime)
        {
            ++directionUpdates;
            out->opaque8 = 0x5678; // Native boundary marker; production encodes its own angles.
        }
    }
    void *memset(void *out, int value, size_t count)
    {
        auto *bytes = static_cast<volatile uint8_t *>(out);
        for (size_t i = 0; i < count; ++i) bytes[i] = uint8_t(value);
        return out;
    }
    void *memcpy(void *out, const void *in, size_t count)
    {
        auto *to = static_cast<volatile uint8_t *>(out);
        auto *from = static_cast<const volatile uint8_t *>(in);
        for (size_t i = 0; i < count; ++i) to[i] = from[i];
        return out;
    }
}

#define CHECK(value) do { if (!(value)) return __LINE__; } while (0)
extern "C" __declspec(dllexport) int Test_Run()
{
    Setup();
    Candidate(0, 1, "br_loot_cache", 1);
    Candidate(1, 2, "brloot_weapon_m4_lege", 5); // Obstructed weapon loses to usable cache.
    Candidate(2, 3, "brloot_weapon_generic_me", 1);
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(scans == 1 && uses == 1 && usedIndex == 1 && usedGeneration == 3 && !usedAuto);
    CHECK(tlsValue == reinterpret_cast<void *>(0x1111));
    Vec3 goal{};
    CHECK(!SV_HostBot_GetLootGoal(&bot, &goal));
    SVHS_LevelTime = 2100;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 1); // Rejected/full inventory callback is not hammered repeatedly.
    provided.count = 0;
    Candidate(0, 4, "brloot_weapon_m4_lege", 0); // In display range but not use cone.
    SVHS_LevelTime = 3200;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 1 && SV_HostBot_GetLootGoal(&bot, &goal) && goal.x == 32);
    bot.look = {{7, 8, 9}, 3100, 0xaabbccdd, 2};
    CHECK(SV_HostBot_FaceLoot(&bot, &command));
    CHECK(lookRequests == 1 && directionUpdates == 1 && command.opaque8 == 0x5678);
    CHECK(bot.look.point.x == 7 && bot.look.point.y == 8 && bot.look.point.z == 9 &&
          bot.look.endTime == 3100 && bot.look.type == 2 && bot.look.opaque16 == 0xaabbccdd);
    CHECK(tlsValue == reinterpret_cast<void *>(0x1111));
    sentient.targetHandle = 1;
    CHECK(!SV_HostBot_FaceLoot(&bot, &command) && directionUpdates == 1);
    sentient.targetHandle = 0;
    bot.look.type = 5;
    bot.look.endTime = 4000;
    CHECK(!SV_HostBot_FaceLoot(&bot, &command) && directionUpdates == 1);
    bot.look.type = 3;
    CHECK(SV_HostBot_FaceLoot(&bot, &command) && directionUpdates == 2);
    CHECK(bot.look.type == 3 && bot.look.endTime == 4000);
    bot.look.type = 2;
    bot.scriptFlags |= 8;
    CHECK(!SV_HostBot_FaceLoot(&bot, &command) && directionUpdates == 2);
    bot.scriptFlags &= ~8u;
    CHECK(SV_HostBot_FaceLoot(&bot, &command) && directionUpdates == 3);
    CHECK(bot.look.type == 2 && bot.look.endTime == 4000);
    ++generations[4];
    CHECK(!SV_HostBot_GetLootGoal(&bot, &goal)); // Reused Scriptable cannot keep old goal.
    provided.items[0].flags = 1;
    SVHS_LevelTime = 4300;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2 && usedIndex == 4 && usedGeneration == 4);
    needsWeapon = false;
    provided.count = 0;
    Candidate(0, 5, "brloot_weapon_m4_lege", 1);
    Candidate(1, 6, "brloot_armor_plate", 1);
    positions[6].z = 500;
    SVHS_LevelTime = 5400;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2); // Equipped bot does not churn weapons; upper floor rejected.
    positions[6].z = 16;
    Field<uint32_t>(client, 22336) = 0x400;
    SVHS_LevelTime = 6500;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2 && !SV_HostBot_GetLootGoal(&bot, &goal)); // Gulag arena.
    Field<uint32_t>(client, 22336) = 0;
    firing = true;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2);
    firing = false;
    Field<uint32_t>(player, 28) = 0x800;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2); // Downed/laststand.
    Field<uint32_t>(player, 28) = 0;
    skydiving = true;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2); // Explicit native skydive state.
    skydiving = false;
    Field<uint16_t>(player, 626) = 2047;
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 2); // Airborne/skydive.
    Field<uint16_t>(player, 626) = 0;
    SVHS_LevelTime = 600; // New map/server timer rollback resets attempt ownership.
    provided.count = 0;
    Candidate(0, 1, "br_loot_cache", 1);
    SV_HostBot_UpdateLoot(&bot, &command);
    CHECK(uses == 3 && usedIndex == 1);
    // Each native update admits at most four lists across the whole server frame.
    const unsigned before = scans;
    for (unsigned i = 1; i < 12; ++i)
    {
        entity.number = int16_t(i);
        SV_HostBot_UpdateLoot(&bot, &command); // First update assigns per-slot stagger.
    }
    SVHS_LevelTime = 5000;
    for (unsigned i = 1; i < 12; ++i)
    {
        entity.number = int16_t(i);
        SV_HostBot_UpdateLoot(&bot, &command);
    }
    CHECK(scans - before == 4);
    CHECK(tlsValue == reinterpret_cast<void *>(0x1111));
    return 0;
}
