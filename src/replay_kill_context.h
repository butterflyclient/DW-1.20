#pragma once
#include <array>
#include <cstdint>

// Generated from 48 original ScriptFile writes (46 named modifier bits).
// Both words share Param1. Unknown bits remain in the packet.
enum class ReplayKillModifier : uint64_t
{
    Oneshotkill = UINT64_C(1),
    Cooking = UINT64_C(2),
    Backstab = UINT64_C(4),
    Ads = UINT64_C(8),
    Hipfire = UINT64_C(16),
    Mounted = UINT64_C(32),
    LastBulletKill = UINT64_C(64),
    VictimSprinting = UINT64_C(128),
    Sliding = UINT64_C(256),
    ProneKill = UINT64_C(512),
    CrouchKill = UINT64_C(1024),
    Quickscope = UINT64_C(2048),
    LowHealthKill = UINT64_C(4096),
    WeaponChangeKill = UINT64_C(8192),
    WeaponPickupKill = UINT64_C(16384),
    ReloadKill = UINT64_C(65536),
    SecondaryWeapon = UINT64_C(131072),
    LastStand = UINT64_C(4398046511104),
    VictimLastStand = UINT64_C(8796093022208),
    InVehicle = UINT64_C(17592186044416),
    VictimInVehicle = UINT64_C(35184372088832),
    ReconDroneExplosive = UINT64_C(140737488355328),
    VehicleExplosive = UINT64_C(281474976710656),
    Longshot = UINT64_C(262144),
    Pointblank = UINT64_C(524288),
    Headshot = UINT64_C(1048576),
    Avenger = UINT64_C(2097152),
    Posthumous = UINT64_C(8388608),
    Revenge = UINT64_C(16777216),
    Firstblood = UINT64_C(33554432),
    Buzzkill = UINT64_C(67108864),
    Comeback = UINT64_C(134217728),
    Backfire = UINT64_C(32768),
    Quadfeed = UINT64_C(536870912),
    Assault = UINT64_C(1073741824),
    Defender = UINT64_C(4194304),
    Insmoke = UINT64_C(2199023255552),
    EnemyHasUAV = UINT64_C(4294967296),
    KillEnemyTeam = UINT64_C(8589934592),
    KilledNemesis = UINT64_C(68719476736),
    Kingslayer = UINT64_C(17179869184),
    Grenadestuck = UINT64_C(34359738368),
    Impaired = UINT64_C(274877906944),
    Gunbutt = UINT64_C(549755813888),
    Tripledefenderkill = UINT64_C(137438953472),
    Execution = UINT64_C(1099511627776),
};

// Original native LuaFile BRLOOT.itemRarities.
enum class ReplayLootRarity : uint16_t
{
    Common = 0,
    Uncommon = 1,
    Rare = 2,
    Epic = 3,
    Legendary = 4,
    Player = 5,
    Mission = 6,
    SpecialMission = 7,
    Unknown = 65535,
};

namespace replay_kill_context
{
    inline constexpr std::array<uint16_t, 3> OverkillPerks = {2, 26, 44};
    inline constexpr uint16_t Oden = 17;
    inline constexpr uint16_t Fal = 21;
    inline constexpr uint16_t M13 = 19;
    inline constexpr uint16_t Thermal = 5;
    inline constexpr uint16_t ThermalHybrid = 7;
} // namespace replay_kill_context
