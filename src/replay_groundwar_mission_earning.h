#pragma once
#include <array>
#include <cstdint>
#include "replay_kill_event.h"
#include "replay_objective_event.h"

namespace replay_groundwar_mission_earning
{
    inline constexpr std::array<uint32_t, 4> StageIds = {1515, 1572, 1591, 10048};

    // Native gametypestable arm -> LUA_MENU_MP/ARMSRACE -> Ground War.
    // Original initchallengeandeventglobals binds arm to 32. The caller
    // admits only complete capture packets from its eligible public MP match.
    inline uint64_t captureProgress(uint32_t stage, const ReplayObjectiveEvent &event)
    {
        return (stage == 1515 || stage == 1572 || stage == 1591) &&
               event.gameType() == ReplayChallengeGameType::arm;
    }

    // Original native weapon/stat/localize tables bind iw8_pi_decho to ID3
    // and .50 GS. A victim vehicle or another pistol cannot satisfy the stage.
    inline uint64_t killProgress(uint32_t stage, const ReplayKillEvent &event)
    {
        return stage == 10048 && event.targets(ReplayKillTarget::Player) &&
               event.gameType() == ReplayChallengeGameType::arm && event.weapon() == 3;
    }
} // namespace replay_groundwar_mission_earning
