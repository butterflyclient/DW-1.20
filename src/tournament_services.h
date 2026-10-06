#pragma once
#include "services.h"
#include "../third_party/nlohmann/json.hpp"

namespace services
{
    // Called only after matchmaking validates the request's authenticated party tokens.
    std::optional<Reply> startTournamentSearch(const std::filesystem::path &directory,
                                               const platform::LobbyIdentity &identity,
                                               const nlohmann::json &query);
    std::optional<Delivery> currentTournamentDelivery(const std::filesystem::path &directory,
                                                      uint32_t title,
                                                      uint64_t user);
    bool tournamentDeliveryValid(const std::filesystem::path &directory,
                                 uint32_t title,
                                 const Delivery &delivery);
    std::optional<Reply> tournamentServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &identity,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &params);
} // namespace services
