#pragma once
#include "services.h"
#include <optional>

namespace services
{
    uint32_t matchmakingHostAuthorized(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &identity,
                                       uint64_t lobby,
                                       std::span<const uint64_t> participants);
    bool matchmakingDeliveryValid(const std::filesystem::path &directory,
                                  uint32_t title,
                                  const Delivery &delivery);
    std::optional<Reply> matchmakingServices(const std::filesystem::path &directory,
                                             const platform::LobbyIdentity &identity,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &parameters);
} // namespace services
