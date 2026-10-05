#pragma once
#include "services.h"

namespace services
{
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
