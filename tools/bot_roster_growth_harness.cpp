// Actual roster source at isolated native record boundaries; no game or users.
#include "../integration/replay/DW_BotRoster.cpp"
#include <stdarg.h>

namespace
{
    BotRecord pool[200]{};
    bool humans[200]{};
    bool nativeBot = false, nativeDW = true;
    unsigned nativeBotCalls = 0;
    DWBotNativeClient profileClient{};
    HostScale::Entity profileEntity{};
    uint8_t profilePlayer[64496]{};
    uint8_t party[100000]{};
    bool Equal(const BotRecord &a, const BotRecord &b)
    {
        const auto *left = reinterpret_cast<const uint8_t *>(&a);
        const auto *right = reinterpret_cast<const uint8_t *>(&b);
        for (unsigned i = 0; i < sizeof(BotRecord); ++i)
            if (left[i] != right[i]) return false;
        return true;
    }
    void NativeSelection(unsigned generation)
    {
        for (unsigned i = 0; i < 200; ++i)
        {
            pool[i] = {};
            auto *bytes = reinterpret_cast<uint8_t *>(&pool[i]);
            for (unsigned n = 50; n < 84; ++n) bytes[n] = uint8_t(generation + i + n);
            pool[i].nameIndex = uint16_t(i);
            pool[i].skill = uint16_t(generation + i);
            pool[i].valid = 1;
        }
    }
}
extern "C"
{
    void *memset(void *out, int value, size_t count)
    {
        auto *bytes = static_cast<volatile uint8_t *>(out);
        for (size_t i = 0; i < count; ++i) bytes[i] = uint8_t(value);
        return out;
    }
    void __chkstk() { __builtin_trap(); } // unrelated UI bodies must never execute here
    uint8_t replay_rva_0c27e4b0[80000]{};
    int DW_Bot_CustomizationEnabled = 0;
    uint8_t DW_Bot_CustomizationPackages[1]{}, DW_Bot_CustomizationGroups[1]{};
    const char *DW_Bot_NameTable = "fixture";
    uint32_t DW_Bot_ClientCount = 0;
    DWBotNativeClient *DW_Bot_Clients[200]{};
    bool DW_LocalBackend_IsEnabled() { return nativeDW; }
    bool DW_BotRank_Apply(unsigned) { return false; } // separate original/native rank fixture
    bool func_140CA2250() { return true; }
    const void *func_140CA2230(unsigned slot) { return &pool[slot]; }
    void *func_140CA2210(unsigned slot) { return &pool[slot]; }
    bool func_14118E020(const void *, unsigned slot) { return humans[slot]; }
    void DW_Bot_StringTableAsset(const char *, const void **out) { *out = nullptr; }
    int DW_Bot_StringTableRows(const void *) { return 0; }
    const char *DW_Bot_StringTableColumn(const void *, unsigned, unsigned) { return "native"; }
    void func_1412B0570(int, const char *, ...) {}
    bool func_141187FA0() { return true; }
    void *func_141187EE0() { return party; }
    bool func_14118E1F0(const void *, unsigned slot) { return humans[slot]; }
    bool func_14118EE80(const void *, unsigned) { return false; }
    bool func_14118E0E0(const void *, unsigned) { return false; }
    bool func_140CA1C80() { return true; }
    bool func_140CA2270(unsigned slot) { return pool[slot].valid; }
    bool func_141359F90(unsigned) { ++nativeBotCalls; return nativeBot; }
    bool func_141371450(unsigned) { return false; }
    void *func_14137D670() { return party; }
    void *func_14118CF60(uint64_t *out, const void *, unsigned slot) { *out = slot; return out; }
    int func_14118C070(const void *, uint64_t) { return 0; }
    int func_14118C110(const void *, uint64_t) { return 0; }
    const char *func_14107EA60(const uint64_t *) { return "fixture"; }
    unsigned char gl_14E183D00[200 * 88]{}, gl_14EEF12A4[1]{}, g_partyData[100000]{};
    int gl_14EEF1288[1]{};
    dvar_t *gl_14D386988{}, *gl_14D386990{}, *gl_14C796328{};
    void func_141B23610(const void *, int *) {}
    void func_141B22140(const void *, unsigned, uint16_t, int) {}
    bool func_141528240() { return false; }
    bool func_140F22880() { return false; }
    void func_140F23A00(const void *, uint16_t, int *, int *) {}
    bool func_14118DDB0(const void *) { return false; }
    unsigned func_14118C7D0(const void *) { return 200; }
    uint16_t func_141B0D390(uint16_t, const char *) { return 0; }
    void func_141B0E150(uint16_t, int) {}
    void func_141B0E0B0(uint16_t, bool) {}
    void func_141B0E280(uint16_t, const char *) {}
    uint16_t func_141B0D520() { return 0; }
    uint16_t func_141B0D710(uint16_t, const char *) { return 0; }
    int func_141B0D530(uint16_t) { return 0; }
    bool func_141192AC0(const void *) { return false; }
    bool func_141192AA0(const void *) { return false; }
    uint32_t Dvar_GenerateChecksum(const char *) { return 0; }
    dvar_t *Dvar_RegisterInt(const char *, int32_t, int32_t, int32_t, uint32_t, const char *) { return nullptr; }
    dvar_t *Dvar_RegisterVariant(const char *, uint32_t, uint8_t, uint32_t,
                               const void *, const void *, const char *) { return nullptr; }
    void Com_Printf(int, const char *, ...) {}
    int Com_sprintf(char *out, size_t size, const char *format, ...)
    {
        va_list args; va_start(args, format);
        const char *name = va_arg(args, const char *);
        unsigned suffix = va_arg(args, unsigned);
        va_end(args);
        size_t used = 0;
        for (; *name; ++name)
        {
            if (used + 1 >= size) return -1;
            out[used++] = *name;
        }
        unsigned place = 1;
        while (place <= suffix / 10) place *= 10;
        do
        {
            if (used + 1 >= size) return -1;
            out[used++] = char('0' + suffix / place);
            suffix %= place; place /= 10;
        } while (place);
        out[used] = 0;
        return int(used);
    }
}

#define CHECK(condition) if (!(condition)) return __LINE__
extern "C" __declspec(dllexport) int Test_Run()
{
    humans[0] = true;
    *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656) = 1;
    NativeSelection(100);
    DW_BotPolicy_BuildRoster(party, 152, 2);
    const BotRecord first = pool[1], second = pool[2];
    CHECK(first.valid && second.valid && !SameName(first.name, second.name));
    DW_BotPolicy_CaptureRoster();
    NativeSelection(1000);
    DW_BotPolicy_BuildRoster(party, 152, 5);
    CHECK(Equal(pool[1], first) && Equal(pool[2], second));
    const BotRecord third = pool[3];
    DW_BotPolicy_CaptureRoster();
    NativeSelection(2000);
    DW_BotPolicy_BuildRoster(party, 152, 3);
    CHECK(Equal(pool[1], first) && Equal(pool[2], second) && Equal(pool[3], third));
    CHECK(!pool[4].valid && !pool[5].valid);
    humans[2] = true;
    DW_BotPolicy_CaptureRoster();
    NativeSelection(3000);
    DW_BotPolicy_BuildRoster(party, 152, 3);
    CHECK(Equal(pool[1], first) && !pool[2].valid && Equal(pool[3], third) && Equal(pool[4], second));
    humans[2] = false;
    DW_BotPolicy_CaptureRoster();
    NativeSelection(4000);
    DW_BotPolicy_BuildRoster(party, 200, 199);
    for (unsigned i = 1; i < 200; ++i)
    {
        CHECK(pool[i].valid);
        for (unsigned other = i + 1; other < 200; ++other)
            CHECK(!SameName(pool[i].name, pool[other].name));
    }
    const auto priorModel = pool[1].modelIndex[0];
    auto &human = reinterpret_cast<MemberRecord *>(party + 2192)[0];
    for (unsigned i = 0; i < sizeof(human.name); ++i) human.name[i] = pool[1].name[i];
    DW_BotPolicy_BuildRoster(party, 200, 199);
    CHECK(!SameName(human.name, pool[1].name) && pool[1].modelIndex[0] == priorModel);
    *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656) = 2;
    NativeSelection(6000);
    DW_BotPolicy_BuildRoster(party, 152, 2);
    CHECK(pool[1].skill == 6000 && pool[2].skill == 6001);
    return 0;
}

extern "C" __declspec(dllexport) unsigned Test_ProfileOwnership(unsigned scenario)
{
    nativeDW = true;
    nativeBot = true;
    nativeBotCalls = 0;
    profileEntity = {};
    profileEntity.number = 7;
    profileEntity.client = profilePlayer;
    HostScale::Field<int32_t>(profilePlayer, 448) = 7;
    profileClient.entity = &profileEntity;
    profileClient.clientType = 2;
    DW_Bot_ClientCount = 8;
    DW_Bot_Clients[7] = &profileClient;
    auto *record = reinterpret_cast<BotRecord *>(gl_14E183D00);
    *record = {};
    record->valid = record->inUse = 1;
    record->client = 7;
    record->nameIndex = 100;
    record->skill = 3;
    switch (scenario)
    {
    case 1: DW_Bot_ClientCount = 7; break;
    case 2: DW_Bot_ClientCount = 201; break;
    case 3: DW_Bot_Clients[7] = nullptr; break;
    case 4: profileClient.clientType = 0; break;
    case 5: profileClient.entity = nullptr; break;
    case 6: profileEntity.number = 8; break;
    case 7: profileEntity.client = nullptr; break;
    case 8: HostScale::Field<int32_t>(profilePlayer, 448) = 8; break;
    case 9: nativeBot = false; break;
    case 10: record->valid = 0; break;
    case 11: record->inUse = 0; break;
    case 12: record->client = 8; break;
    case 13: nativeDW = false; break;
    }
    uint64_t seed = 0xdeadbeef;
    const bool found = DW_BotPolicy_ProfileSeed(7, &seed);
    if (found != (scenario == 0)) return 1;
    if (scenario && seed != 0xdeadbeef) return 2;
    const bool called = scenario == 0 || (scenario >= 9 && scenario <= 12);
    if (nativeBotCalls != unsigned(called)) return 3;
    nativeDW = true;
    nativeBot = false;
    return 0;
}
