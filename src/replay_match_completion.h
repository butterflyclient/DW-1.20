#pragma once
#include <array>
#include <cstdint>
#include "replay_challenge_game_type.h"

// Original stopkeyearning emits 0 for an unclassified result, 1 for a win,
// 2 for a loss, 3 for a team tie. In FFA, the native win is qualified top three.
enum class ReplayMatchOutcome : uint64_t
{
    Unclassified = 0,
    Win = 1,
    Loss = 2,
    Tie = 3,
};

struct ReplayMatchCompletion
{
    std::array<uint64_t, 5> parameters;

    ReplayChallengeGameType gameType() const
    {
        // Upper word contains packed operators, not part of the game type.
        return static_cast<ReplayChallengeGameType>(static_cast<uint32_t>(parameters[0]));
    }

    bool completed() const { return parameters[1] >= 1 && parameters[1] <= 3; }
    bool won() const { return parameters[1] == static_cast<uint64_t>(ReplayMatchOutcome::Win); }

    // Caller requires a complete packet from the first native end of its
    // eligible active public MP match, matching the start's specific mode.
    bool matches(uint32_t stage) const
    {
        if (!completed())
            return false;
        switch (stage)
        {
        case 1500:
        case 1511:
            return true;
        case 1504:
        case 1568:
        case 1579:
            return won();
        case 1574:
            return won() && gameType() == ReplayChallengeGameType::sd;
        case 1578:
            return won() && gameType() == ReplayChallengeGameType::arena;
        case 1587:
            return gameType() == ReplayChallengeGameType::arena;
        case 1593:
            return won() && gameType() == ReplayChallengeGameType::cyber;
        default:
            return false;
        }
    }
};
