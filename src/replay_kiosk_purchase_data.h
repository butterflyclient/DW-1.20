#pragma once
#include <array>
#include <cstdint>
#include <string_view>

// Generated from the native Replay mp/brkioskpurchases.csv and
// mp/achievementenginerefs.csv; all ten shipped purchase rows retained.
enum class ReplayKioskCategory : uint64_t
{
    Special = 1,
    Killstreak = 2,
    TeamRevive = 3,
    FieldUpgrade = 4,
};

enum class ReplayKioskItem : uint64_t
{
    ArmorBundle = 0,
    ManualTurret = 3,
    TomaStrike = 4,
    GasMask = 1,
    PrecisionAirstrike = 2,
    Uav = 5,
    SelfReviveToken = 6,
    Teamrevive = 7,
    SuperAmmoDrop = 8,
    SupplyDrop = 9,
};

struct ReplayKioskPurchase
{
    ReplayKioskItem id;
    ReplayKioskCategory category;
    std::string_view name;
};

inline constexpr std::array<ReplayKioskPurchase, 10> replayKioskPurchases = {{
    {ReplayKioskItem::ArmorBundle, ReplayKioskCategory::Special, "armor_bundle"},
    {ReplayKioskItem::ManualTurret, ReplayKioskCategory::Killstreak, "manual_turret"},
    {ReplayKioskItem::TomaStrike, ReplayKioskCategory::Killstreak, "toma_strike"},
    {ReplayKioskItem::GasMask, ReplayKioskCategory::Special, "gas_mask"},
    {ReplayKioskItem::PrecisionAirstrike, ReplayKioskCategory::Killstreak, "precision_airstrike"},
    {ReplayKioskItem::Uav, ReplayKioskCategory::Killstreak, "uav"},
    {ReplayKioskItem::SelfReviveToken, ReplayKioskCategory::Special, "self_revive_token"},
    {ReplayKioskItem::Teamrevive, ReplayKioskCategory::TeamRevive, "teamrevive"},
    {ReplayKioskItem::SuperAmmoDrop, ReplayKioskCategory::FieldUpgrade, "super_ammo_drop"},
    {ReplayKioskItem::SupplyDrop, ReplayKioskCategory::Special, "supply_drop"},
}};
