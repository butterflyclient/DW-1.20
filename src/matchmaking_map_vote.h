#pragma once
#include "platform.h"
#include "../third_party/nlohmann/json.hpp"
#include <filesystem>

namespace services::map_vote
{
    bool pending(const nlohmann::json &lobby);
    void update(const std::filesystem::path &directory, const platform::LobbyIdentity &identity,
                nlohmann::json &lobby, nlohmann::json &host);
    void publish(const nlohmann::json &lobby, nlohmann::json &overrides);
    void validate(const nlohmann::json &lobby);
}
