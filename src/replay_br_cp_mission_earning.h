#pragma once
#include <array>
#include <cstdint>
#include "replay_kill_event.h"

namespace replay_br_cp_mission_earning
{
    inline constexpr std::array<uint32_t, 11> Top15Stages = {
        50018, 50025, 50032, 50039, 50046, 50053,
        50060, 50067, 50074, 50081, 50088};

    // Native ProcessParams: match_placement(game type, placement, operators).
    // Caller retains complete-packet and public match ownership checks.
    inline bool placementMatches(uint32_t stage, const std::array<uint64_t, 3> &packet)
    {
        if (packet[0] != static_cast<uint32_t>(ReplayChallengeGameType::br) ||
            packet[1] == 0 || packet[1] > 15)
            return false;
        for (const auto id : Top15Stages)
            if (stage == id)
                return true;
        return false;
    }

    inline bool killMatches(uint32_t stage, const ReplayKillEvent &kill)
    {
        return stage == 50017 && kill.gameType() == ReplayChallengeGameType::br &&
               kill.targets(ReplayKillTarget::Player) &&
               kill.hasModifier(ReplayKillModifier::VictimLastStand);
    }
} // namespace replay_br_cp_mission_earning
