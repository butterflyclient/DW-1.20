#include "sv_host_navigation.h"
#include "SV_BotThinkBindings.h"
#include "DW_BotStyleProfile.h"
#include <intrin.h>
#include <xmmintrin.h>

extern "C" bool DW_BotPolicy_IsBattleRoyale();

namespace
{
    using namespace HostScale;

    struct BotInfoView
    {
        Entity *entity;
        Sentient *sentient;
        void *sentientInfo;
        uint8_t opaque24[336];
        void *navigator;
        uint8_t opaque368[80];
        void *player;
        UserCmd *lastCommand;
        uint32_t flags;
        uint8_t opaque468[8516];
        uint32_t scriptFlags;
    };

    static_assert(offsetof(BotInfoView, navigator) == 360);
    static_assert(offsetof(BotInfoView, player) == 448);
    static_assert(offsetof(BotInfoView, lastCommand) == 456);
    static_assert(offsetof(BotInfoView, flags) == 464);
    static_assert(offsetof(BotInfoView, scriptFlags) == 8984);

    struct MatchCombatView
    {
        uint32_t flags;
        uint8_t opaque4[28];
        float adsDelayHip, adsDelayScoped;
        float minBurstTime, maxBurstTime, minBurstGap, maxBurstGap;
        uint8_t opaque56[148];
        uint32_t burstType;
    };

    static_assert(offsetof(MatchCombatView, minBurstTime) == 40);
    static_assert(offsetof(MatchCombatView, burstType) == 204);

    void Combat(BotInfoView *info, UserCmd *command)
    {
        auto *ps = info->player;
        // The native combat pipeline still decides whether to shoot, melee,
        // throw a grenade, reload or wait for an ADS/weapon transition. Change
        // only the match preferences during this one serialized native call.
        uint64_t profile = 0;
        bool battleRoyale = false;
        bool equipmentPreference = false;
        bool policy = Enabled() &&
                      DW_BotPolicy_ProfileSeed(uint16_t(info->entity->number), &profile) &&
                      Field<uint32_t>(ps, 12) <= 1 && !(Field<uint8_t>(info, 620) & 0x1F) &&
                      !(info->scriptFlags & 0x1000) && !(Field<uint32_t>(ps, 1796) & 0x400) &&
                      Field<int32_t>(info, 28208) <= SVHS_LevelTime;
        const unsigned handle = info->sentient->targetHandle;
        policy = policy && handle && handle <= 2048 && BT_EntityInUse[handle - 1];
        if (policy)
        {
            battleRoyale = DW_BotPolicy_IsBattleRoyale();
            auto *enemy = reinterpret_cast<Entity *>(BT_Entities + 1440 * (handle - 1));
            TeamFlags hostile{};
            SVHS_EnemyTeamFlags(&hostile, info->sentient->team);
            const unsigned team = enemy->sentient ? enemy->sentient->team : 160;
            policy = enemy->health > 0 && team < 160 &&
                     (hostile.words[team >> 5] & (0x80000000u >> (team & 31))) &&
                     (!battleRoyale || !(Field<uint32_t>(info->entity->client, 22336) & 0x200)) &&
                     !BT_IsSkydiving(ps);
            const float x = enemy->origin.x - info->entity->origin.x;
            const float y = enemy->origin.y - info->entity->origin.y;
            const float z = enemy->origin.z - info->entity->origin.z;
            const float rangeSquared = x * x + y * y + z * z;
            equipmentPreference = policy && rangeSquared >= 128.0f * 128.0f &&
                                  rangeSquared <= 2048.0f * 2048.0f &&
                                  (!battleRoyale ||
                                   !(Field<uint32_t>(info->entity->client, 22336) & 0x600));
        }
        if (!policy)
        {
            BT_Combat(info, command);
            return;
        }
        void *weapon = BT_ViewWeapon(ps);
        if (BT_WeaponNone(weapon) || !BT_IsRanged(ps, weapon) || BT_IsWeaponClass(ps, weapon, 6))
        {
            BT_Combat(info, command);
            return;
        }
        auto *match =
            reinterpret_cast<MatchCombatView *>(reinterpret_cast<uint8_t *>(info) + 32484);
        const uint32_t originalFlags = match->flags, originalBurst = match->burstType;
        const bool alternate =
            !(Field<uint32_t>(ps, 1800) & 4) && (Field<uint32_t>(ps, 1796) & 0x8020000);
        const int fireType = BT_WeaponFireType(weapon, alternate);
        if (BT_CanFire(info) && (fireType == 0 || fireType == 5)) // Native FULLAUTO / BEAM.
            match->burstType = 0; // Native BOT_BURST_FIRE_TYPE_NONE.
        match->flags |= 2; // Request native Bot_ShouldADS, including its weapon/dual/hip checks.
        if (equipmentPreference)
            // Bot_UpdateCombat and its native grenade selector consume bit 0.
            // They choose an owned lethal/tactical, require ammo and legal
            // weapon/cook states, preserve cooldowns, solve a safe throw arc,
            // then select 0x1000/0x2000 from the actual equipped offhand.
            match->flags |= 1;
        BT_Combat(info, command);
        // Native combat may return before refreshing lastADS while waiting for
        // aim, ammunition or a firing opportunity. Try its ADS eligibility after
        // that decision, with the preference still active. Keep grenade/melee
        // actions intact; final native Bot_ShouldPressADS still owns the button.
        if (!(command->buttons & (0x3000 | 4)) && BT_ADSAllowed(info, info->player))
            Field<int32_t>(info, 29208) = SVHS_LevelTime;
        match->flags = originalFlags;
        match->burstType = originalBurst;
    }

    void Frozen(void *client, UserCmd *command)
    {
        Field<int32_t>(client, 30560) = SVHS_LevelTime;
        Field<uint64_t>(command, 24) = 0;
        Field<uint32_t>(command, 32) = 0;
        Field<uint16_t>(command, 156) = 0;
    }

    void Finalize(UserCmd *command)
    {
        command->serverTime = command->commandTime = command->inputTime =
            Field<int32_t>(BT_Persistent, 28);
    }

    void SetStatics(void *statics)
    {
        auto *slots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
        *reinterpret_cast<void **>(slots[SVHS_BotTlsIndex] + 16) = statics;
    }

    bool MeshReady(BotInfoView *info)
    {
        // The native mesh mode can have a valid navigator with no tactical
        // asset. Continue the native brain only on its real, owned current area.
        // A pathnode bot or a disconnected/invalid navigator keeps native fallback.
        if (!Enabled() || !(info->scriptFlags & 0x1000000) || !info->navigator)
            return false;
        const auto *nav = static_cast<Nav2DQueryView *>(info->navigator);
        return nav->vtable && nav->vtable[45] == reinterpret_cast<uintptr_t>(&SVHS_Nav2DClosest) &&
               nav->currentArea.reference && *nav->currentArea.reference && nav->currentArea.space;
    }
} // namespace

extern "C" void Bot_Think(void *client, HostScale::UserCmd *command)
{
    using namespace HostScale;
    auto *info = reinterpret_cast<BotInfoView *>(static_cast<uint8_t *>(client) + 1368);
    const int slot = int(
        (reinterpret_cast<intptr_t>(client) - reinterpret_cast<intptr_t>(BT_ClientBase)) / 321192);
    // A pooled bot command must never follow a reused client slot or stale
    // entity/player pointer into a human's state. Revalidate before native think
    // mutates the brain; command submission independently owns its same guard.
    if (Enabled() &&
        (!client || slot < 0 || slot >= 200 || unsigned(slot) >= SVHS_ClientCount ||
         SVHS_Clients[slot] != client || Field<int32_t>(client, 214756) != 2 || !info->entity ||
         Field<Entity *>(client, 280) != info->entity || info->entity->number != slot ||
         info->entity->client != info->player || info->entity->sentient != info->sentient ||
         !SVHS_IsBotEntity(info->entity) || !SVHS_IsBotPlaying(client)))
    {
        *command = {};
        return;
    }
    void *player = BT_PlayerState(slot);
    command->serverTime = command->commandTime = command->inputTime = 0;
    if (!info->entity)
        return;
    *command = *info->lastCommand;
    command->buttons = 0;
    BT_RoundRobin(info);
    const uint8_t skydive = Field<uint8_t>(info->player, 12072);
    if (!Field<int32_t>(client, 1988) && !(skydive & 0xFA) && skydive != 1)
        BT_NavSetPos(info->navigator, &info->entity->origin);
    void *remotePlayer = Field<void *>(BT_EntityData(info->entity), 448);
    if (Field<uint32_t>(remotePlayer, 20) & 0x10000000)
    {
        const int16_t remote = Field<int16_t>(remotePlayer, 144);
        if (remote != 2047)
        {
            auto *entity = reinterpret_cast<Entity *>(BT_Entities + 1440 * remote);
            if (entity->type == 4 && (Field<uint8_t>(entity, 492) & 0x80))
                command->buttons |= 0x40000;
        }
    }
    Sentient *sentient = info->entity->sentient;
    if (!sentient || !sentient->team || sentient->team == 153 ||
        Field<int32_t>(BT_PausedDvar, 40) || BT_LocalPaused())
    {
        Frozen(client, command);
        Finalize(command);
        return;
    }
    if (Field<uint32_t>(info->entity->client, 24016) & 4)
    {
        command->buttons |= info->lastCommand->buttons & (0x80 | 0x40 | 8);
        Frozen(client, command);
        if (BT_WeaponNone(BT_ViewWeapon(player)))
            BT_WeaponUpdate(info, command);
        if (!(Field<uint32_t>(info->entity->client, 24016) & 0x400))
            BT_Direction(info, command);
        Finalize(command);
        return;
    }
    const bool archived = BT_ArchiveTime(slot) != 0;
    if (info->entity->health <= 0 || archived || (Field<uint32_t>(player, 20) & 0x8000))
    {
        BT_InvalidateNode(info->sentient);
        BT_InvalidateTac(info->sentient);
        BT_ClearWeapon(command, info->player);
        Finalize(command);
        return;
    }
    SetStatics(SVHS_GameStatics);
    if (BT_DisableNearest)
        BT_PrintError(18,
                      "Using bots when g_DisablePlayerNearestDataUpdates is true - bots will not "
                      "function properly!\n");
    if (Field<uint8_t>(BT_DisableRepulsorsDvar, 40))
        BT_PrintError(18,
                      "Using bots when g_DisablePlayerRepulsors is true - bots will not function "
                      "properly!\n");
    const bool requirePathnodes = !(Field<uint8_t>(client, 10355) & 1);
    if ((requirePathnodes && !BT_NearestNode(sentient)) ||
        (!requirePathnodes && !BT_NearestTac(sentient) && !MeshReady(info)))
    {
        BT_Strafe(info);
        BT_OffGridMove(info, command);
        if (BT_ScriptedScene(player))
            BT_WeaponUpdate(info, command);
        else
            BT_ClearWeapon(command, info->player);
        SetStatics(nullptr);
        Finalize(command);
        return;
    }
    // Native awareness, target selection and combat order. No synthetic point,
    // enemy, command or navigation data is installed to make this path reachable.
    if (SVHS_LevelTime > Field<int32_t>(client, 30568) + 2200)
    {
        if (!BT_PlayerExcluded(info->player) && !BT_BotExcluded(info))
        {
            for (unsigned i = 0; i < 64; ++i)
            {
                const int16_t number = BT_RadarEntities[i];
                if (number == 2047 || !BT_EntityInUse[number])
                    continue;
                auto *entity = reinterpret_cast<Entity *>(BT_Entities + 1440 * number);
                if (!entity)
                    continue;
                const uint32_t flags = entity->client ? Field<uint32_t>(entity->client, 364)
                                                      : Field<uint32_t>(entity, 12);
                const int16_t owner = entity->client ? entity->number : Field<int16_t>(entity, 2);
                if ((flags & 0x200000) && BT_EntityInUse[owner] && info->entity->number == owner)
                    BT_RadarEvent(info, &entity->origin, 500.0f, 26);
            }
            if (Field<uint8_t>(BT_RadarDvar, 40))
                BT_RadarEvent(info, &info->entity->origin, 9999.0f, 26);
            else if (Field<uint8_t>(info->player, 756))
                BT_RadarEvent(info, &info->entity->origin, 500.0f, 26);
        }
        Field<int32_t>(client, 30568) = SVHS_LevelTime + BT_RandomInt(50, 200);
    }
    BT_XRay(info);
    BT_Sight(info, command);
    BT_Threat(info);
    BT_EnemyTrack(info);
    if (info->sentient->targetHandle)
    {
        auto *enemy =
            reinterpret_cast<Entity *>(BT_Entities + 1440 * (info->sentient->targetHandle - 1));
        if (enemy)
        {
            const float x = info->entity->origin.x - enemy->origin.x;
            const float y = info->entity->origin.y - enemy->origin.y;
            const float z = info->entity->origin.z - enemy->origin.z;
            Field<float>(client, 10436) =
                _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss((y * y + x * x) + z * z)));
        }
    }
    BT_RiotShield(info);
    BT_WeaponUpdate(info, command);
    BT_Movement(info, command);
    BT_Doors(info);
    void *ps = info->player;
    if (!(Field<uint8_t>(client, 1988) & 0x1F))
    {
        void *weapon = BT_ViewWeapon(ps);
        if (!BT_WeaponNone(weapon))
        {
            const uint32_t stance = Field<uint32_t>(info->player, 364);
            if ((BT_ADSDesire(info) || (stance & 0xE0)) && BT_ADSAllowed(info, ps))
            {
                void *node = BT_NearestNode(info->sentient);
                if (node)
                {
                    const int close = (stance & 0xE0) ? 1 : int(Field<int8_t>(client, 29524));
                    const float distance = BT_NodeDistance(node, Field<float>(ps, 464), close);
                    const float range =
                        BT_SniperADS(info) ? 1000.0f : BT_WeaponRange(ps, weapon) * 1.25f;
                    if (distance > range)
                    {
                        Field<int32_t>(client, 30576) = SVHS_LevelTime;
                        Field<int32_t>(client, 30588) = SVHS_LevelTime;
                    }
                }
            }
            if (BT_CanFire(info) &&
                BT_WeaponRange(ps, weapon) * 0.75f < Field<float>(client, 10436))
                Field<int32_t>(client, 30588) = SVHS_LevelTime;
        }
    }
    Combat(info, command);
    ps = info->player;
    if (!BT_Reload(info, command))
    {
        if (BT_Underbarrel(BT_MapViewWeapon(BT_WeaponMap(), ps)))
        {
            Field<uint32_t>(ps, 1796) |= 0x20000;
            BT_Reload(info, command);
            Field<uint32_t>(ps, 1796) &= ~0x20000u;
        }
    }
    ps = info->player;
    const int32_t lastADS = Field<int32_t>(client, 30576);
    if (BT_PressADS(info) && lastADS > 0 && SVHS_LevelTime - lastADS <= 500)
    {
        command->buttons |= 0x200;
        if (BT_CanHoldBreath(ps))
        {
            if (Field<float>(ps, 1804) >= 1.0f)
            {
                if (SVHS_LevelTime > Field<int32_t>(client, 29304) && !Field<int32_t>(ps, 836))
                {
                    Field<int32_t>(client, 29300) = BT_RandomFloat() < Field<float>(client, 34032);
                    Field<int32_t>(client, 29304) = SVHS_LevelTime + BT_BreathTime(ps);
                }
                if (Field<int32_t>(client, 29300))
                    command->buttons |= 0x800;
            }
            else
                Field<int32_t>(client, 29304) = SVHS_LevelTime + BT_RandomInt(0, 3000);
        }
        else
            Field<uint64_t>(client, 29300) = 0;
    }
    BT_ScriptButtons(info, command);
    ps = info->player;
    void *weapon = BT_ViewWeapon(ps);
    if (Field<uint16_t>(weapon, 0) && !BT_IsFiring(info, command))
    {
        const bool alternate =
            ps && !(Field<uint32_t>(ps, 1800) & 4) && (Field<uint32_t>(ps, 1796) & 0x8020000);
        const bool dual = !BT_IsSkydiving(ps) && BT_DualWield(ps) && Field<uint32_t>(ps, 1872) == 1;
        void *gesture1 = BT_Gesture(ps, nullptr, weapon, alternate, dual, 47);
        void *gesture2 = BT_Gesture(ps, nullptr, weapon, alternate, dual, 48);
        const bool playing1 = BT_GesturePlaying(ps, gesture1, nullptr, nullptr);
        const bool playing2 = BT_GesturePlaying(ps, gesture2, nullptr, nullptr);
        if (!playing1 && !playing2 &&
            (((Field<uint32_t>(client, 10352) >> 23) ^ (Field<uint32_t>(ps, 1796) >> 7)) & 1))
            command->buttons |= 0x10000;
    }
    BT_ScreenTargets(info);
    BT_MeleeCharge(info, command);
    if (BT_VariableZoom(info))
    {
        int minimum = 0, maximum = 3000;
        bool change = true;
        if (BT_InADS(info->player))
        {
            const bool pressed = (BT_Feature(126) && (info->lastCommand->buttons & 0x2000000)) ||
                                 (BT_Feature(126) && (command->buttons & 0x2000000));
            change = SVHS_LevelTime - Field<int32_t>(client, 10492) > 500 &&
                     SVHS_LevelTime > Field<int32_t>(client, 30584) && !pressed;
            if (change)
            {
                command->buttons |= 0x2000000;
                minimum = 1000;
                maximum = 6000;
            }
        }
        if (change)
            Field<int32_t>(client, 30584) = SVHS_LevelTime + BT_RandomInt(minimum, maximum);
    }
    BT_Hybrid(info, command);
    if (Field<int32_t>(client, 29316))
    {
        weapon = BT_ViewWeapon(info->player);
        if (!BT_WeaponNone(weapon) && BT_ActiveUnderbarrel(weapon))
            BT_UnderbarrelAmmo(weapon);
    }
    if (BT_IsFiring(info, command))
        Field<int32_t>(client, 30604) = SVHS_LevelTime;
    if (BT_Compare(static_cast<uint8_t *>(static_cast<void *>(command)) + 36,
                   static_cast<uint8_t *>(static_cast<void *>(info->lastCommand)) + 36,
                   60))
        Field<uint32_t>(info, 27888) = 0;
    info->flags &= ~0x60u;
    if (info->flags & 8)
        BT_PathClear(info);
    BT_ClientNotifies(info, command);
    SetStatics(nullptr);
    Finalize(command);
}
