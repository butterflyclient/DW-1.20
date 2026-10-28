#pragma once
#include "../third_party/nlohmann/json.hpp"
#include <filesystem>
#include <optional>
#include <set>

namespace services
{
    struct PlaylistSelection
    {
        nlohmann::json rules;
        nlohmann::json metadata;
        unsigned teamCount = 0;
        unsigned squadSize = 0;
        unsigned maximumMembers = 0; // zero only when no native capacity rule is published
        bool splitPartiesForTeamBalance = false;
    };

    std::optional<PlaylistSelection> selectPlaylist(const std::filesystem::path &directory,
                                                    uint32_t title,
                                                    const nlohmann::json &query,
                                                    const std::string &requiredMap = {},
                                                    unsigned preferredPlaylist = 0);

    // Playlists a search for that playlist alone can start: the selector above
    // finds at least one eligible map entry under the published policy and the
    // installed-map inventory. Empty when no catalog is published.
    std::set<unsigned> servablePlaylists(const std::filesystem::path &directory, uint32_t title);
} // namespace services
