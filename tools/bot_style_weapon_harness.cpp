#include "DW_BotStyleSelection.h"
#include "DW_BotBindings.h"
#include "DW_ScriptMethodBindings.h"
#include "sv_host_bot_equipment.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

extern "C" void DW_BotStyleWeaponMethod(void *, uint64_t);
extern "C" void DW_BotSurvivalAllowedMethod(void *, uint64_t);
extern "C" void DW_BotMPClassReadyMethod(void *, uint64_t);
extern "C"
{
    void *SVHS_Clients[200]{};
    uint32_t SVHS_ClientCount = 200;
    uint32_t DW_Bot_ClientCount = 200;
    DWBotNativeClient *DW_Bot_Clients[200]{};
}

namespace
{
    struct Fixture
    {
        HostScale::BotWeapon original{}, candidate{}, returned{};
        HostScale::Entity entity{};
        uint8_t player[22340]{};
        uint8_t nativeClient[321192]{};
        alignas(2) uint8_t weaponTable[70596]{};
        uint64_t self = 33, profile = 1;
        unsigned params = 2, adds = 0, parses = 0, validations = 0;
        unsigned survivalCalls = 0, boolAdds = 0;
        int returnedBool = -1;
        bool survivalAllowed = true;
        int slot = -1;
        uint8_t alternate = 0;
        bool bot = true, br = false, sky = false, parse = true, valid = true, entityPresent = true,
             returnedAlternate = false;
        const char *base = "iw8_ar_mike4_mp";
        std::string name;

        Fixture()
        {
            for (unsigned i = 0; i < sizeof(original); ++i)
                reinterpret_cast<uint8_t *>(&original)[i] = uint8_t(i * 3 + 19);
            for (unsigned i = 0; i < sizeof(candidate); ++i)
                reinterpret_cast<uint8_t *>(&candidate)[i] = uint8_t(i * 7 + 5);
            original.index = 1;
            candidate.index = 77;
            entity.number = 33;
            entity.health = 100;
            entity.client = player;
            HostScale::Field<int32_t>(player, 448) = 33;
            auto *owner = reinterpret_cast<DWBotNativeClient *>(nativeClient);
            owner->entity = &entity;
            owner->clientType = 2;
            DW_Bot_ClientCount = 200;
            DW_Bot_Clients[33] = owner;
            *reinterpret_cast<uint16_t *>(weaponTable + 70594) = 0;
        }
    } *current;

    void *const context = reinterpret_cast<void *>(uintptr_t(0x12340));

    void CheckContext(void *value)
    {
        assert(value == context);
    }

    void Original(const Fixture &fixture)
    {
        assert(fixture.adds == 1);
        assert(!memcmp(&fixture.returned, &fixture.original, sizeof(fixture.original)));
        assert(fixture.returnedAlternate == bool(fixture.alternate));
    }

    void Run(Fixture &fixture)
    {
        current = &fixture;
        DW_BotStyleWeaponMethod(context, fixture.self);
    }

    void ValidateProfile(const Fixture &fixture)
    {
        assert(fixture.adds == 1 && fixture.parses == 1 && fixture.validations == 1 &&
               !fixture.returnedAlternate);
        assert(!memcmp(&fixture.returned, &fixture.candidate, sizeof(fixture.candidate)));
        const auto *weapon =
            fixture.br ? DWBotStyle::FindWeapon(fixture.base)
                       : DWBotStyle::WeaponForSlot(fixture.profile, unsigned(fixture.slot));
        assert(weapon);
        // The lobby publishes this shared profile selection. Compare its generic
        // UI references through the generated native-name/variant join to the
        // callback's parsed native tokens rather than reproducing FullName.
        const auto selected =
            DWBotStyle::Select(weapon, fixture.profile, DWBotStyle::SelectStyle(fixture.profile));
        assert(fixture.name.substr(0, fixture.name.find('+')) == weapon->nativeAsset);
        // The Python gate compares the complete native recipe against the
        // original stock Lua/table rules, including mandatory parts and combos.
        printf("RECIPE\t%s\t", weapon->reference);
        for (unsigned i = 0; i < selected.count; ++i)
            printf("%s%s|%u", i ? "," : "", selected.references[i], selected.variants[i]);
        printf("\t%s\n", fixture.name.c_str());
    }
} // namespace

extern "C" void SM_GetWeaponParam(void *ctx, uint32_t index, void *weapon, uint8_t *alternate)
{
    CheckContext(ctx);
    assert(index == 0);
    memcpy(weapon, &current->original, 60);
    *alternate = current->alternate;
}

extern "C" uint32_t SM_GetNumParam(void *ctx)
{
    CheckContext(ctx);
    return current->params;
}

extern "C" void *SM_GetEntity(uint64_t self)
{
    assert(self == current->self);
    return current->entityPresent ? &current->entity : nullptr;
}

extern "C" bool DW_BotPolicy_ProfileSeed(unsigned client, uint64_t *seed)
{
    assert(client == unsigned(current->entity.number));
    *seed = current->profile;
    return current->bot;
}

extern "C" bool DW_BotPolicy_IsBattleRoyale()
{
    return current->br;
}

extern "C" int32_t SM_GetInt(void *ctx, uint32_t index)
{
    CheckContext(ctx);
    assert(index == 1);
    return current->slot;
}

extern "C" const char *SM_GetWeaponBaseName(const void *weapon, bool alternate)
{
    assert(!alternate && !memcmp(weapon, &current->original, 60));
    return current->base;
}

extern "C" bool SVHBL_IsSkydiving(const void *player)
{
    assert(player == current->player);
    return current->sky;
}

extern "C" void *SM_FindBaseWeapon(void *, const char *)
{
    assert(false && "Native resource finder is a parser boundary in this fixture");
    return nullptr;
}

extern "C" bool SM_ParseFullWeapon(const char *name,
                                   void *output,
                                   void *(*finder)(void *, const char *))
{
    assert(finder == SM_FindBaseWeapon);
    current->name = name;
    ++current->parses;
    memcpy(output, &current->candidate, 60);
    return current->parse;
}

extern "C" bool SM_IsValidWeapon(const void *weapon, bool alternate)
{
    assert(!alternate && !memcmp(weapon, &current->candidate, 60));
    ++current->validations;
    return current->valid;
}

extern "C" const void *SM_GetWeaponTable(const void *ctx)
{
    CheckContext(const_cast<void *>(ctx));
    return current->weaponTable;
}

extern "C" void SM_AddWeaponParam(void *ctx, const void *weapon, bool alternate)
{
    CheckContext(ctx);
    ++current->adds;
    memcpy(&current->returned, weapon, 60);
    current->returnedAlternate = alternate;
}

extern "C" bool SV_HostBot_AllowSurvival(void *data)
{
    assert(data == current->nativeClient + 1368);
    ++current->survivalCalls;
    return current->survivalAllowed;
}

extern "C" void SM_AddBool(void *ctx, int32_t value)
{
    CheckContext(ctx);
    assert(value == 0 || value == 1);
    ++current->boolAdds;
    current->returnedBool = value;
}

int main()
{
    unsigned profiles = 0, preserved = 0;
    const uint32_t models[]{53, 80, 0};
    for (unsigned id = 0; id < 150; ++id)
    {
        for (int slot = 0; slot < 2; ++slot)
        {
            Fixture fixture;
            fixture.slot = slot;
            fixture.profile = DWBotStyle::ProfileSeed(uint16_t(id), 3, models);
            Run(fixture);
            ValidateProfile(fixture);
            ++profiles;
        }
        Fixture fixture;
        fixture.br = true;
        fixture.profile = DWBotStyle::ProfileSeed(uint16_t(id), 3, models);
        Run(fixture);
        ValidateProfile(fixture);
        ++profiles;
    }
    for (int health : {0, -10})
        for (int slot = 0; slot < 2; ++slot)
        {
            Fixture fixture;
            fixture.entity.health = health;
            fixture.slot = slot;
            Run(fixture);
            ValidateProfile(fixture);
            ++profiles;
        }
    // A dead BR pickup is not MP class construction and stays untouched.
    {
        Fixture fixture;
        fixture.entity.health = 0;
        fixture.br = true;
        Run(fixture);
        Original(fixture);
        ++preserved;
    }
    for (unsigned scenario = 0; scenario < 19; ++scenario)
    {
        Fixture fixture;
        switch (scenario)
        {
        case 0:
            fixture.bot = false;
            break;
        case 1:
            fixture.original.index = 0;
            break;
        case 2:
            fixture.alternate = 1;
            break;
        case 3:
            fixture.self |= uint64_t(10) << 32;
            break;
        case 4:
            fixture.self = 200;
            break;
        case 5:
            fixture.entityPresent = false;
            break;
        case 6:
            fixture.entity.client = nullptr;
            break;
        case 7:
            fixture.entity.health = 0;
            break;
        case 8:
            fixture.br = true;
            *reinterpret_cast<uint32_t *>(fixture.player + 22336) = 0x200;
            break;
        case 9:
            fixture.br = true;
            *reinterpret_cast<uint32_t *>(fixture.player + 22336) = 0x400;
            break;
        case 10:
            fixture.br = true;
            fixture.sky = true;
            break;
        case 11:
            fixture.br = true;
            fixture.base = "iw8_pi_golf21_mp";
            break;
        case 12:
            fixture.base = "unsupported_item";
            break;
        case 13:
            fixture.slot = 5;
            break;
        case 14:
            fixture.parse = false;
            break;
        case 15:
            fixture.valid = false;
            break;
        case 16:
            fixture.candidate.index = 0;
            break;
        case 17:
            fixture.params = 1;
            break;
        case 18:
            fixture.base = nullptr;
            break;
        }
        Run(fixture);
        Original(fixture);
        ++preserved;
    }
    // BR loadout construction never substitutes an MP profile weapon. Its
    // native starter is kept before pickups; slot -1 remains pickup styling.
    for (int slot = 0; slot < 2; ++slot)
    {
        Fixture fixture;
        fixture.br = true;
        fixture.slot = slot;
        Run(fixture);
        Original(fixture);
        ++preserved;
    }
    unsigned capacityCases = 0;
    for (unsigned scenario = 0; scenario < 6; ++scenario)
    {
        Fixture fixture;
        fixture.slot = 0;
        memset(fixture.weaponTable, 0xff, sizeof(fixture.weaponTable));
        const auto *bytes = reinterpret_cast<const uint8_t *>(&fixture.candidate);
        uint32_t hash = 0;
        for (unsigned i = 0; i < 60; ++i)
            hash = (hash * 0x1000193u) ^ bytes[i];
        hash *= 0x1000193u; // alternate is false
        hash *= 0x1000193u; // native reserved byte is zero
        if (scenario == 0)
            *reinterpret_cast<uint16_t *>(fixture.weaponTable + 70594) = 999;
        if (scenario >= 2 && scenario <= 4)
        {
            *reinterpret_cast<uint16_t *>(fixture.weaponTable + 68000 + 2 * (hash % 1297)) = 999;
            memcpy(fixture.weaponTable + 999 * 62, &fixture.candidate, 60);
            fixture.weaponTable[999 * 62 + 60] = scenario == 3 ? 1 : 0;
            if (scenario == 4)
                fixture.weaponTable[999 * 62 + 59] ^= 1;
        }
        if (scenario == 5)
            *reinterpret_cast<uint16_t *>(fixture.weaponTable + 70594) = 1000;
        Run(fixture);
        if (scenario == 0 || scenario == 2)
            ValidateProfile(fixture);
        else
            Original(fixture);
        ++capacityCases;
    }
    unsigned ownershipCases = 0;
    for (unsigned scenario = 0; scenario < 10; ++scenario)
    {
        Fixture fixture;
        fixture.slot = 0;
        switch (scenario)
        {
        case 0: DW_Bot_ClientCount = 33; break;
        case 1: DW_Bot_ClientCount = 201; break;
        case 2: DW_Bot_Clients[33] = nullptr; break;
        case 3: DW_Bot_Clients[33]->clientType = 0; break;
        case 4: DW_Bot_Clients[33]->entity = nullptr; break;
        case 5: fixture.entity.number = 34; break;
        case 6: fixture.entity.client = nullptr; break;
        case 7: HostScale::Field<int32_t>(fixture.player, 448) = 34; break;
        case 8: fixture.self = 32; break;
        case 9: fixture.entity.health = 0; break;
        }
        Run(fixture);
        if (scenario == 9)
        {
            // MP class construction is permitted before spawn/while dead.
            assert(fixture.parses == 1 && fixture.validations == 1 && fixture.adds == 1);
            assert(!memcmp(&fixture.returned, &fixture.candidate, sizeof(fixture.candidate)));
        }
        else
        {
            Original(fixture);
            assert(fixture.parses == 0 && fixture.validations == 0);
        }
        ++ownershipCases;
    }
    assert(ownershipCases == 10);
    unsigned survivalCases = 0;
    unsigned mpClassCases = 0;
    for (unsigned scenario = 0; scenario < 12; ++scenario)
    {
        Fixture fixture;
        current = &fixture;
        fixture.params = 0;
        switch (scenario)
        {
        case 1: fixture.entity.health = 0; break; // pre-spawn managed MP allowed
        case 2: DW_Bot_Clients[33]->clientType = 0; break; // human
        case 3: fixture.bot = false; break; // generic bot without managed profile
        case 4: fixture.br = true; break; // native starter and Gulag excluded
        case 5: fixture.self |= uint64_t(10) << 32; break;
        case 6: DW_Bot_ClientCount = 33; break;
        case 7: fixture.bot = false; break; // pending pool binding
        case 8: HostScale::Field<int32_t>(fixture.player, 448) = 0; break;
        case 9: DW_Bot_Clients[33]->entity = nullptr; break;
        case 10: fixture.params = 1; break;
        case 11: fixture.entityPresent = false; break;
        }
        DW_BotMPClassReadyMethod(context, fixture.self);
        assert(fixture.boolAdds == 1 && !fixture.adds && !fixture.parses);
        assert(fixture.returnedBool == (scenario < 2 ? 1 : 0));
        ++mpClassCases;
    }
    assert(mpClassCases == 12);
    for (unsigned scenario = 0; scenario < 12; ++scenario)
    {
        Fixture fixture;
        fixture.br = true;
        current = &fixture;
        SVHS_ClientCount = 200;
        SVHS_Clients[33] = fixture.nativeClient;
        if (scenario == 1)
            fixture.br = false;
        if (scenario == 2)
            fixture.bot = false;
        if (scenario == 3)
            fixture.self |= uint64_t(10) << 32;
        if (scenario == 4)
            fixture.self = 200;
        if (scenario == 5)
            SVHS_ClientCount = 33;
        if (scenario == 6)
            SVHS_Clients[33] = nullptr;
        // The native survival owner rejects dead/airborne/Gulag/last-stand/
        // combat/locked states. This fixture models its false result and proves
        // that the script predicate preserves it, with the exact botData ABI.
        if (scenario >= 7)
            fixture.survivalAllowed = false;
        DW_BotSurvivalAllowedMethod(context, fixture.self);
        assert(fixture.boolAdds == 1 && !fixture.adds);
        assert(fixture.returnedBool == (scenario == 0 ? 1 : 0));
        assert(fixture.survivalCalls == (scenario == 0 || scenario >= 7 ? 1u : 0u));
        ++survivalCases;
    }
    printf(
        "PASS: %u callback weapon recipes match lobby profile data; %u full Weapon60/alternate "
        "preservation gates; %u survival predicate ABI/gates; %u managed-table capacity gates; "
        "%u managed MP class readiness gates. "
        "Native parsing/resources modeled.\n",
        profiles,
        preserved,
        survivalCases,
        capacityCases,
        mpClassCases);
}
