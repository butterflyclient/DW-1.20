#pragma once
#include "services.h"

namespace services
{
    bool tournamentDeliveryValid(const std::filesystem::path &directory,
                                 uint32_t title,
                                 const Delivery &delivery);
    std::optional<Reply> tournamentServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &identity,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &params);
} // namespace services
