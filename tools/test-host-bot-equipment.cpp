#include "../integration/host-scale/SV_HostBotEquipment.cpp"
#include <assert.h>
#include <stdio.h>

extern "C" { int32_t SVHS_LevelTime = 1000; void *SVHS_GameStatics = nullptr; }

namespace
{
    using namespace HostScale;
    BotWeaponEntry entries[8]{};
    BotWeaponMap map{nullptr, entries};
    BotEquipmentPlayer player{};
    Entity entity{};
    BotEquipmentData bot{};
    bool battleRoyale = true;
    unsigned switches;

    void Reset()
    {
        battleRoyale = false;
        SV_HostBot_PrepareEquipment(&bot);
        player = {};
        entity = {};
        bot = {};
        entity.health = 100;
        bot.entity = &entity;
        bot.player = &player;
        battleRoyale = true;
        switches = 0;
    }
}

extern "C" bool DW_BotPolicy_IsBattleRoyale() { return battleRoyale; }
extern "C" HostScale::BotWeaponMap *SVHBE_WeaponMap() { return &map; }
extern "C" bool SVHBE_IsMelee(const HostScale::BotEquipmentPlayer *, const HostScale::BotWeapon *w)
{ return w->index == 1; }
extern "C" bool SVHBE_IsRanged(const HostScale::BotEquipmentPlayer *, const HostScale::BotWeapon *w)
{ return w->index == 2 || w->index == 3 || w->index == 4; }
extern "C" int SVHBE_WeaponClass(const HostScale::BotWeapon *w, bool)
{ return w->index == 2 ? 5 : w->index == 4 ? 6 : 2; }
extern "C" const char *SVHBE_WeaponName(const HostScale::BotWeapon *w, char *, unsigned)
{ return w->index == 1 ? "iw8_fists_mp" : "other"; }
extern "C" bool SVHBE_SwitchWeapon(HostScale::Entity *, const HostScale::BotWeapon *w)
{
    if (w->index)
    {
        bool owned = false;
        for (const auto handle : player.inventory)
            owned |= entries[uint16_t(handle)].weapon.index == w->index;
        assert(owned);
    }
    bot.scriptWeapon = *w;
    ++switches;
    return true;
}

int main()
{
    for (unsigned i = 0; i != 8; ++i)
    {
        entries[i].mapIndex = uint16_t(i);
        entries[i].weapon.index = uint16_t(i);
    }
    entries[3].weapon.configuration[17] = 9; // Preserve the assigned attachment data.

    Reset();
    player.inventory[0] = 2; player.inventory[1] = 1;
    player.currentWeapon = 1; bot.scriptWeapon = entries[1].weapon;
    assert(SV_HostBot_NeedsRangedWeapon(&bot));
    assert(SV_HostBot_PrepareEquipment(&bot) && !bot.scriptWeapon.index);
    assert(!SV_HostBot_PrepareEquipment(&bot) && switches == 1);
    bot.scriptWeapon = entries[1].weapon; // A subsequent deliberate melee choice survives.
    assert(!SV_HostBot_PrepareEquipment(&bot) && bot.scriptWeapon.index == 1);

    player.gameExtraInfo = 0x200;
    player.inventory[0] = 1; player.inventory[1] = 4; // Fists plus rocks.
    player.currentWeapon = 0; bot.scriptWeapon = entries[2].weapon;
    assert(SV_HostBot_InGulag(&bot));
    assert(SV_HostBot_NeedsRangedWeapon(&bot)); // A projectile rock is not a primary.
    assert(SV_HostBot_PrepareEquipment(&bot) && bot.scriptWeapon.index == 1);
    assert(player.inventory[1] == 4 && !SV_HostBot_PrepareEquipment(&bot));

    player.gameExtraInfo = 0x400;
    player.inventory[0] = 3; player.inventory[1] = 1; player.inventory[2] = 5;
    assert(SV_HostBot_PrepareEquipment(&bot));
    assert(memcmp(&bot.scriptWeapon, &entries[3].weapon, sizeof(bot.scriptWeapon)) == 0);
    assert(!SV_HostBot_NeedsRangedWeapon(&bot));
    assert(player.inventory[2] == 5 && !SV_HostBot_PrepareEquipment(&bot));

    player.gameExtraInfo = 0;
    bot.scriptWeapon = entries[1].weapon;
    assert(SV_HostBot_PrepareEquipment(&bot) && !bot.scriptWeapon.index);
    battleRoyale = false; bot.scriptWeapon = entries[1].weapon;
    assert(!SV_HostBot_PrepareEquipment(&bot) && bot.scriptWeapon.index == 1);
    battleRoyale = true; entity.health = 0;
    assert(!SV_HostBot_PrepareEquipment(&bot));
    entity.health = 100;
    assert(SV_HostBot_PrepareEquipment(&bot) && !bot.scriptWeapon.index);
    puts("BR equipment lifecycle: passed (starter, jail rocks, native duel attachments, melee, primary loot, death and mode gates)");
}
