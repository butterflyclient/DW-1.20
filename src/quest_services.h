#pragma once
#include "services.h"
#include "marketplace_services.h"
#include "replay_daily_challenges.h"
#include <map>
#include <set>
#include <string>

namespace services
{
    // Admission alone never establishes public-match/category eligibility.
    bool replayQuestEventMayEarn(const std::string &name);
    struct QuestProgress
    {
        nlohmann::json states;
        std::map<uint32_t, bool> updates;
        std::map<uint32_t, uint32_t> successors;
        std::set<uint32_t> items;
        uint64_t xp = 0;
        // Per-life/rapid/minute trackers advanced without completing progress.
        bool stateChanged = false;
    };

    struct ReplayQuestEventContext
    {
        std::optional<unsigned> category;
        uint64_t activationCutoff = UINT64_MAX;
        uint64_t nativeMatch = 0;
        bool firstEnd = false;
        bool firstPlacement = false;
    };

    const ReplayDailyChallenge *replayDailyChallenge(uint64_t identity);
    bool synchronizeReplayDailies(nlohmann::json &states, uint64_t now);
    QuestProgress advanceReplayDailies(const nlohmann::json &states,
                                      const nlohmann::json &events,
                                      std::span<const ReplayQuestEventContext> contexts,
                                      uint64_t now);
    std::vector<Delivery> replayDailyUpdates(const platform::LobbyIdentity &identity,
                                           const std::string &context,
                                           const QuestProgress &progress,
                                           bool refresh = false);

    // Original Replay parser fields and shipped mission criteria only.
    // Unbound producer predicates leave their selected stages unchanged.
    QuestProgress advanceReplayQuests(const nlohmann::json &states,
                                       const nlohmann::json &events,
                                       std::optional<unsigned> publicCategory);
    QuestProgress advanceReplayQuests(const nlohmann::json &states,
                                       const nlohmann::json &events,
                                       std::span<const ReplayQuestEventContext> publicContexts);
    std::vector<Delivery> replayQuestUpdates(const platform::LobbyIdentity &identity,
                                              const std::string &context,
                                              const QuestProgress &progress,
                                              const RankInventory *inventory,
                                              bool refresh = false);
    bool replayQuestDeliveryValid(const nlohmann::json &states, const Delivery &delivery);
} // namespace services
