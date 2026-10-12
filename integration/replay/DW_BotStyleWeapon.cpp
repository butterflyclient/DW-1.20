#include "DW_BotStyleProfile.h"
#include "DW_BotStyleSelection.h"
#include "DW_ScriptMethodBindings.h"
#include "SV_HostBotLootBindings.h"
#include "sv_host_bot_equipment.h"
#include "sv_host_bot_loot.h"
#include <stddef.h>

extern "C" bool DW_BotPolicy_IsBattleRoyale();

namespace
{
    struct ManagedWeapon
    {
        HostScale::BotWeapon weapon;
        uint8_t alternate;
        uint8_t reserved;
    };

    // Complete native GScrWeaponTable embedded in the script context. Its
    // existing allocator and reference counts remain owned by the script VM.
    struct ManagedWeaponTable
    {
        ManagedWeapon data[1000];
        uint16_t references[1000];
        uint16_t next[1000];
        uint16_t previous[1000];
        uint16_t buckets[1297];
        uint16_t free;
    };
    static_assert(sizeof(ManagedWeapon) == 62);
    static_assert(offsetof(ManagedWeapon, alternate) == 60);
    static_assert(sizeof(ManagedWeaponTable) == 70596);
    static_assert(offsetof(ManagedWeaponTable, references) == 62000);
    static_assert(offsetof(ManagedWeaponTable, next) == 64000);
    static_assert(offsetof(ManagedWeaponTable, previous) == 66000);
    static_assert(offsetof(ManagedWeaponTable, buckets) == 68000);
    static_assert(offsetof(ManagedWeaponTable, free) == 70594);

    bool CanIntern(void *context, const HostScale::BotWeapon &weapon, bool alternate)
    {
        const auto *table = static_cast<const ManagedWeaponTable *>(SM_GetWeaponTable(context));
        if (!table)
            return false;
        if (table->free != 0xffff)
            return table->free < 1000;
        // A full table can still reuse an exact existing managed weapon. Match
        // the original allocator's 62-byte hash and 60-byte/alternate equality.
        const ManagedWeapon candidate{weapon, uint8_t(alternate), 0};
        const auto *bytes = reinterpret_cast<const uint8_t *>(&candidate);
        uint32_t hash = 0;
        for (unsigned i = 0; i < sizeof(candidate); ++i)
            hash = (hash * 0x1000193u) ^ bytes[i];
        uint16_t entry = table->buckets[hash % 1297];
        for (unsigned visited = 0; entry < 1000 && visited < 1000; ++visited)
        {
            const auto &existing = table->data[entry];
            bool equal = existing.alternate == uint8_t(alternate);
            const auto *existingBytes = reinterpret_cast<const uint8_t *>(&existing.weapon);
            for (unsigned i = 0; equal && i < sizeof(weapon); ++i)
                equal = existingBytes[i] == bytes[i];
            if (equal)
                return true;
            entry = table->next[entry];
        }
        return false;
    }

    bool Append(char *output, unsigned capacity, unsigned &length, const char *text)
    {
        while (*text)
        {
            if (length + 1 >= capacity)
                return false;
            output[length++] = *text++;
        }
        output[length] = 0;
        return true;
    }

    bool FullName(const DWBotStyle::Weapon &weapon, const DWBotStyle::Selection &selection,
                  char *output, unsigned capacity)
    {
        unsigned length = 0;
        if (!Append(output, capacity, length, weapon.nativeAsset))
            return false;
        for (unsigned i = 0; i < selection.count; ++i)
        {
            if (!Append(output, capacity, length, "+") ||
                !Append(output, capacity, length, selection.resolvedReferences[i]))
                return false;
            if (selection.variants[i])
            {
                char digits[4]{};
                unsigned value = selection.variants[i], count = 0;
                do
                {
                    digits[count++] = char('0' + value % 10);
                    value /= 10;
                } while (value);
                if (!Append(output, capacity, length, "|"))
                    return false;
                while (count)
                {
                    const char digit[2]{digits[--count], 0};
                    if (!Append(output, capacity, length, digit))
                        return false;
                }
            }
        }
        return true;
    }
} // namespace

// Fixed-arity native method: self dw_botstyleweapon(managedWeapon, slot).
// MP slots choose the same profile weapon displayed in the lobby. BR slot -1
// retains the acquired firearm's base while applying its compatible style.
extern "C" void DW_BotStyleWeaponMethod(void *context, uint64_t self)
{
    HostScale::BotWeapon original{};
    uint8_t alternate = 0;
    SM_GetWeaponParam(context, 0, &original, &alternate);
    HostScale::BotWeapon result = original;
    if (SM_GetNumParam(context) == 2 && original.index && !alternate &&
        !((self >> 32) & 0xff) && uint32_t(self) < 200)
    {
        auto *entity = static_cast<HostScale::Entity *>(SM_GetEntity(self));
        uint64_t profile = 0;
        if (entity && entity->client &&
            DW_BotPolicy_ProfileSeed(uint16_t(entity->number), &profile))
        {
            const int slot = SM_GetInt(context, 1);
            const bool br = DW_BotPolicy_IsBattleRoyale();
            const char *base = SM_GetWeaponBaseName(&original, false);
            const bool nativePhase = br &&
                ((HostScale::Field<uint32_t>(entity->client, 22336) & 0x600) ||
                 SVHBL_IsSkydiving(entity->client));
            // Preserve the stock BR starter and every jail/duel/airborne loadout.
            // Unsupported objects and human receivers always return a managed
            // clone of their exact original, never a borrowed table pointer.
            const bool mpClassConstruction = !br && slot >= 0 && slot < 2;
            // MP classes are built before spawn and while dead on respawn.
            // Return a managed class weapon here; BR pickup still requires life.
            if ((entity->health > 0 || mpClassConstruction) && !nativePhase && base &&
                !(br && DWBotStyle::Same(base, "iw8_pi_golf21_mp")))
            {
                const auto *weapon = !br && slot >= 0 && slot < 2
                    ? DWBotStyle::WeaponForSlot(profile, unsigned(slot))
                    : slot == -1 ? DWBotStyle::FindWeapon(base) : nullptr;
                if (weapon)
                {
                    const auto selection = DWBotStyle::Select(weapon, profile,
                                                              DWBotStyle::SelectStyle(profile));
                    char name[1024]{};
                    HostScale::BotWeapon candidate{};
                    if (FullName(*weapon, selection, name, sizeof(name)) &&
                        SM_ParseFullWeapon(name, &candidate, SM_FindBaseWeapon) &&
                        candidate.index && SM_IsValidWeapon(&candidate, false) &&
                        CanIntern(context, candidate, false))
                        result = candidate;
                }
            }
        }
    }
    SM_AddWeaponParam(context, &result, alternate != 0);
}

extern "C" void DW_BotSurvivalAllowedMethod(void *context, uint64_t self)
{
    bool allowed = false;
    if (!((self >> 32) & 0xff) && uint32_t(self) < 200 &&
        DW_BotPolicy_IsBattleRoyale() && uint32_t(self) < SVHS_ClientCount)
    {
        uint64_t profile = 0;
        if (DW_BotPolicy_ProfileSeed(uint32_t(self), &profile))
        {
            auto *client = SVHS_Clients[uint32_t(self)];
            if (client)
                allowed = SV_HostBot_AllowSurvival(static_cast<uint8_t *>(client) + 1368);
        }
    }
    SM_AddBool(context, allowed ? 1 : 0);
}
