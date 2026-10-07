#pragma once
#include "services.h"

namespace services
{
    void restoreAchievementProgression(const std::filesystem::path &,
                                       uint32_t title, uint64_t user, uint64_t xp,
                                       bool restore, unsigned startingRank);
    std::optional<Reply> achievementServices(const std::filesystem::path &,
                                             const platform::LobbyIdentity &,
                                             uint8_t,
                                             uint8_t,
                                             wire::Reader &);
    Reply achievementEventsRest(const std::filesystem::path &,
                                const platform::LobbyIdentity &,
                                const std::string &,
                                std::span<const uint8_t>);
} // namespace services
