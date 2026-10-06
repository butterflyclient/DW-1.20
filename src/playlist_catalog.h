#pragma once
#include "../third_party/nlohmann/json.hpp"
#include <filesystem>
#include <optional>

namespace services
{
    struct PlaylistSelection
    {
        nlohmann::json rules;
        nlohmann::json metadata;
        unsigned teamCount = 0;
    };

    std::optional<PlaylistSelection> selectPlaylist(const std::filesystem::path &directory,
                                                    uint32_t title,
                                                    const nlohmann::json &query,
                                                    const std::string &requiredMap = {});
} // namespace services
