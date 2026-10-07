#pragma once
#include "services.h"
#include <vector>

namespace services
{
    struct StoredProgression
    {
        uint64_t user = 0, xp = 0;
        std::string name;
    };

    std::vector<StoredProgression> achievementProgressionSnapshot(
        const std::filesystem::path &, uint32_t title, const std::string &context);
    bool achievementDeliveryValid(const std::filesystem::path &, uint32_t title,
                                  const Delivery &);
    std::optional<Delivery> currentProgressionDelivery(const std::filesystem::path &,
                                                      uint32_t title, uint64_t user);
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
