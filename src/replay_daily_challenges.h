#pragma once
#include <array>
#include <cstdint>

// Original Replay daily StringTables have thirteen columns. Keep the unknown
// columns intact; CSV's original Lua contract binds only the named accessors.
// The local assignment policy uses the first three rows per mode each UTC day.
enum class ReplayDailyCriterion { Pending, PlayerKill, Headshot, Melee };
struct ReplayDailyChallenge
{
    uint32_t id;
    uint16_t kind;
    uint32_t target, xpReward, itemReward;
    ReplayDailyCriterion criterion;
    std::array<const char *, 13> sourceFields;
    const char *name() const { return sourceFields[1]; }
    const char *description() const { return sourceFields[3]; }
};

inline constexpr std::array<ReplayDailyChallenge, 9> replayDailyChallenges = {{
    {1797, 12, 20, 2000, 0, ReplayDailyCriterion::PlayerKill, {"1797", "ch_daily_killer_short", "CHALLENGE/DAILY_KILLER", "CHALLENGE/DAILY_KILLER_DESC", "20", "2000", "", "1", "", "", "", "", "12"}},
    {1798, 12, 5, 2000, 0, ReplayDailyCriterion::Headshot, {"1798", "ch_daily_headhunter_short", "CHALLENGE/DAILY_HEADHUNTER", "CHALLENGE/DAILY_HEADHUNTER_DESC", "5", "2000", "", "1", "", "", "", "", "11"}},
    {1799, 12, 3, 2000, 0, ReplayDailyCriterion::Melee, {"1799", "ch_daily_close_and_personal_short", "CHALLENGE/DAILY_CLOSE_AND_PERSONAL", "CHALLENGE/DAILY_CLOSE_AND_PERSONAL_DESC", "3", "2000", "", "1", "", "", "", "", "8"}},
    {5000, 27, 3, 2000, 0, ReplayDailyCriterion::Pending, {"5000", "ch_br_daily_ammo_dealer_short", "CHALLENGE/BR_DAILY_AMMO_DEALER", "CHALLENGE/BR_DAILY_AMMO_DEALER_DESC", "3", "2000", "", "1", "", "", "", "", "15"}},
    {5001, 27, 2, 2000, 0, ReplayDailyCriterion::Pending, {"5001", "ch_br_daily_the_biggest_booms_short", "CHALLENGE/BR_DAILY_THE_BIGGEST_BOOMS", "CHALLENGE/BR_DAILY_THE_BIGGEST_BOOMS_DESC", "2", "2000", "", "1", "", "", "", "", "6"}},
    {5002, 27, 1, 2000, 0, ReplayDailyCriterion::Pending, {"5002", "ch_br_daily_arms_dealer_short", "CHALLENGE/BR_DAILY_ARMS_DEALER", "CHALLENGE/BR_DAILY_ARMS_DEALER_DESC", "1", "2000", "", "1", "", "", "", "", "33"}},
    {9055, 30, 40, 2000, 0, ReplayDailyCriterion::Pending, {"9055", "ch_daily_assault_rifle_kills_short_cp", "CHALLENGE/DAILY_ASSAULT_RIFLE_KILLS", "CHALLENGE/DAILY_ASSAULT_RIFLE_KILLS_DESC", "40", "2000", "", "1", "", "", "", "", "2"}},
    {9056, 30, 10, 2000, 0, ReplayDailyCriterion::Pending, {"9056", "ch_daily_assault_rifle_headshots_short_cp", "CHALLENGE/DAILY_ASSAULT_RIFLE_HEADSHOTS", "CHALLENGE/DAILY_ASSAULT_RIFLE_HEADSHOTS_DESC", "10", "2000", "", "1", "", "", "", "", "3"}},
    {9057, 30, 40, 2000, 0, ReplayDailyCriterion::Pending, {"9057", "ch_daily_smg_kills_short_cp", "CHALLENGE/DAILY_SMG_KILLS", "CHALLENGE/DAILY_SMG_KILLS_DESC", "40", "2000", "", "1", "", "", "", "", "1"}},
}};
