#include "sv_host_bot_equipment.h"
#include "SV_HostBotEquipmentBindings.h"
#include <string.h>

extern "C" bool DW_BotPolicy_IsBattleRoyale();

namespace
{
    using namespace HostScale;

    struct EquipmentTransition
    {
        const BotEquipmentPlayer *player;
        const void *mapStatics;
        uint32_t phase, inventory[15], currentWeapon;
        int32_t lastTime;
        bool valid;
    };

    EquipmentTransition s_transitions[200]{};
    bool s_battleRoyale;

    const BotWeapon &InventoryWeapon(const BotWeaponMap *map, uint32_t handle)
    {
        return map->entries[uint16_t(handle)].weapon;
    }

    bool IsFists(const BotWeapon &weapon)
    {
        if (!weapon.index)
            return false;
        char name[1024];
        return strcmp(SVHBE_WeaponName(&weapon, name, sizeof(name)), "iw8_fists_mp") == 0;
    }

    const BotWeapon *FirstRanged(const BotEquipmentData *bot,
                                 const BotWeaponMap *map,
                                 bool primaryOnly)
    {
        for (const auto handle : bot->player->inventory)
        {
            const auto &weapon = InventoryWeapon(map, handle);
            if (weapon.index && !SVHBE_IsMelee(bot->player, &weapon) &&
                SVHBE_IsRanged(bot->player, &weapon))
            {
                // Rocks and grenades can be projectile weapons but remain
                // offhands. They must never satisfy the firearm requirement.
                const int weaponClass = SVHBE_WeaponClass(&weapon, false);
                if (weaponClass != 6 && (!primaryOnly || weaponClass != 5))
                    return &weapon;
            }
        }
        return nullptr;
    }
} // namespace

extern "C" bool SV_HostBot_InGulag(void *data)
{
    const auto *bot = static_cast<HostScale::BotEquipmentData *>(data);
    return bot && bot->player && (bot->player->gameExtraInfo & 0x600) != 0;
}

extern "C" bool SV_HostBot_NeedsRangedWeapon(void *data)
{
    const auto *bot = static_cast<HostScale::BotEquipmentData *>(data);
    const auto *map = SVHBE_WeaponMap();
    // BR's starter sidearm must not prevent the bot from seeking a primary.
    return bot && bot->player && map && map->entries && !FirstRanged(bot, map, true);
}

extern "C" bool SV_HostBot_PrepareEquipment(void *data)
{
    using namespace HostScale;
    if (!DW_BotPolicy_IsBattleRoyale())
    {
        if (s_battleRoyale)
            for (auto &previous : s_transitions)
                previous.valid = false;
        s_battleRoyale = false;
        return false;
    }
    s_battleRoyale = true;
    auto *bot = static_cast<BotEquipmentData *>(data);
    if (!bot || !bot->entity || !bot->player || bot->entity->number < 0 ||
        unsigned(bot->entity->number) >= 200)
        return false;
    auto &previous = s_transitions[bot->entity->number];
    if (bot->entity->health <= 0)
    {
        previous.valid = false;
        return false;
    }
    const auto *map = SVHBE_WeaponMap();
    if (!map || !map->entries)
        return false;
    const uint32_t phase = bot->player->gameExtraInfo & 0x600;
    const bool lifecycle =
        !previous.valid || previous.player != bot->player ||
        previous.mapStatics != SVHS_GameStatics || SVHS_LevelTime < previous.lastTime ||
        previous.phase != phase ||
        memcmp(previous.inventory, bot->player->inventory, sizeof(previous.inventory)) != 0;
    const bool selectionLost =
        !bot->player->currentWeapon &&
        (!previous.valid || previous.currentWeapon != bot->player->currentWeapon);
    bool corrected = false;
    if (lifecycle || selectionLost)
    {
        if (phase & 0x200)
        {
            // Jail's script owns fists plus rocks. Select its owned melee weapon;
            // native offhand/grenade logic continues to own rock throws.
            for (const auto handle : bot->player->inventory)
            {
                const auto &weapon = InventoryWeapon(map, handle);
                if (IsFists(weapon))
                {
                    if (memcmp(&bot->scriptWeapon, &weapon, sizeof(weapon)) != 0)
                        corrected = SVHBE_SwitchWeapon(bot->entity, &weapon);
                    break;
                }
            }
        }
        else if (phase & 0x400)
        {
            // The duel table has already supplied its primary, attachments and
            // offhands. Resolve that owned weapon rather than manufacture one.
            if (const auto *weapon = FirstRanged(bot, map, false))
                if (memcmp(&bot->scriptWeapon, weapon, sizeof(*weapon)) != 0)
                    corrected = SVHBE_SwitchWeapon(bot->entity, weapon);
        }
        else if (IsFists(bot->scriptWeapon) && FirstRanged(bot, map, false))
        {
            // The spawn/Gulag fists lock must not override the standard pistol.
            // Clear it only at equipment lifecycle changes. Native Bot_Weap_Update
            // chooses the owned gun, respecting its high-priority weapon checks.
            const BotWeapon none{};
            corrected = SVHBE_SwitchWeapon(bot->entity, &none);
        }
    }
    previous.player = bot->player;
    previous.mapStatics = SVHS_GameStatics;
    previous.lastTime = SVHS_LevelTime;
    previous.phase = phase;
    memcpy(previous.inventory, bot->player->inventory, sizeof(previous.inventory));
    previous.currentWeapon = bot->player->currentWeapon;
    previous.valid = true;
    return corrected;
}
