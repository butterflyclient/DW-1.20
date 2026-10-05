#include "playlist_catalog.h"
#include "wire.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        struct CachedDocument
        {
            std::filesystem::file_time_type modified;
            uintmax_t size = 0;
            Json value;
        };

        Json document(const std::filesystem::path &path, uintmax_t maximum, const Json &fallback)
        {
            if (!std::filesystem::exists(path))
                return fallback;
            const auto size = std::filesystem::file_size(path);
            wire::require(size <= maximum);
            const auto modified = std::filesystem::last_write_time(path);
            // services::dispatch serializes access, including catalog refreshes.
            static std::map<std::filesystem::path, CachedDocument> cache;
            const auto found = cache.find(path);
            if (found != cache.end() && found->second.modified == modified &&
                found->second.size == size)
                return found->second.value;
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Playlist catalog read failed");
            auto value = Json::parse(in);
            cache[path] = {modified, size, value};
            return value;
        }

        std::string identifier(const Json &value, size_t capacity)
        {
            wire::require(value.is_string());
            const auto name = value.get<std::string>();
            wire::require(!name.empty() && name.size() < capacity &&
                          std::all_of(name.begin(),
                                      name.end(),
                                      [](unsigned char c)
                                      {
                                          return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                                 (c >= '0' && c <= '9') || c == '_' || c == '.';
                                      }));
            return name;
        }

        unsigned number(const Json &value, unsigned maximum)
        {
            wire::require(value.is_number_integer());
            const auto result = value.get<int64_t>();
            wire::require(result >= 0 && static_cast<uint64_t>(result) <= maximum);
            return static_cast<unsigned>(result);
        }

        void overrides(Json &out, const Json &source, const Json &bindings)
        {
            wire::require(source.is_object());
            for (auto it = source.begin(); it != source.end(); ++it)
            {
                auto name = it.key();
                if (name.starts_with("set "))
                    name.erase(0, 4);
                while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
                    name.pop_back();
                name = identifier(name, 128);
                if (bindings.contains(name))
                    name = identifier(bindings.at(name), 128);
                wire::require(it.value().is_string() || it.value().is_number() ||
                              it.value().is_boolean());
                const auto text =
                    it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
                wire::require(text.size() < 256 && text.find('\0') == std::string::npos);
                out[name] = it.value();
            }
        }

        void assign(Json &out, const Json &bindings, const std::string &name, const Json &value)
        {
            out[bindings.contains(name) ? identifier(bindings.at(name), 128) : name] = value;
        }
    } // namespace

    std::optional<PlaylistSelection> selectPlaylist(const std::filesystem::path &directory,
                                                    uint32_t title,
                                                    const Json &query)
    {
        const auto root = directory / "playlists" / std::to_string(title);
        const auto catalog = document(root / "catalog.json", 409600, Json());
        if (catalog.is_null())
            return std::nullopt;
        wire::require(catalog.is_object() && catalog.at("playlists").is_array() &&
                      catalog.at("gametypes").is_array());
        wire::require(catalog["playlists"].size() <= 128 && catalog["gametypes"].size() <= 64);
        const auto version = number(catalog.at("system").at("version"), UINT32_MAX);
        const auto &filter = query.at("ruleset_payload").at("filter");
        wire::require(filter.is_object());
        if (number(filter.at("playlist_version"), UINT32_MAX) != version)
            return std::nullopt;
        const auto requested = number(filter.at("playlist_id"), 127);
        std::vector<unsigned> candidates{requested};
        if (query.contains("playlist_config"))
        {
            wire::require(query["playlist_config"].is_array() &&
                          query["playlist_config"].size() <= 128);
            for (const auto &group : query["playlist_config"])
            {
                wire::require(group.at("playlist_ids").is_array() &&
                              group["playlist_ids"].size() <= 128);
                for (const auto &value : group["playlist_ids"])
                {
                    const auto id = number(value, 127);
                    if (std::find(candidates.begin(), candidates.end(), id) == candidates.end())
                        candidates.push_back(id);
                }
            }
        }
        const auto policy = document(root / "policy.json", 16384, Json::object());
        wire::require(policy.is_object());
        if (policy.contains("preferred_playlist_id"))
        {
            const auto preferred = number(policy["preferred_playlist_id"], 127);
            const auto match = std::find(candidates.begin(), candidates.end(), preferred);
            if (match != candidates.end())
                std::rotate(candidates.begin(), match, match + 1);
        }
        const auto bindings =
            document(root / "native-dvar-names.json", 1024 * 1024, Json::object());
        wire::require(bindings.is_object());
        std::set<std::string> maps;
        if (policy.contains("available_maps"))
        {
            wire::require(policy["available_maps"].is_array() &&
                          policy["available_maps"].size() <= 256);
            for (const auto &map : policy["available_maps"])
                wire::require(maps.insert(identifier(map, 24)).second);
        }
        std::map<unsigned, Json> playlists;
        std::map<std::string, Json> modes;
        for (const auto &mode : catalog["gametypes"])
        {
            const auto name = identifier(mode.at("gametype"), 32);
            wire::require(modes.emplace(name, mode).second);
            (void)identifier(mode.at("script"), 32);
            if (mode.contains("teamCount"))
                (void)number(mode.at("teamCount"), 200);
        }
        for (const auto &playlist : catalog["playlists"])
        {
            const auto id = number(playlist.at("playlist"), 127);
            wire::require(id && playlists.emplace(id, playlist).second);
            wire::require(playlist.at("maps").is_array() && !playlist["maps"].empty() &&
                          playlist["maps"].size() <= 1024);
            for (const auto &entry : playlist["maps"])
            {
                (void)identifier(entry.at("map"), 24);
                wire::require(modes.contains(identifier(entry.at("gametype"), 32)));
                wire::require(entry.at("weight").is_number() &&
                              std::isfinite(entry["weight"].get<double>()) &&
                              entry["weight"].get<double>() >= 0);
            }
        }
        for (const auto id : candidates)
        {
            const auto found = playlists.find(id);
            if (found == playlists.end())
                continue;
            const auto &playlist = found->second;
            Json weights = Json::object();
            std::vector<Json> eligible;
            // Replay's native ChooseEntry weights the first 20 entries. Every map
            // outside a restricted local installation receives an explicit zero.
            const auto count = std::min(size_t{20}, playlist["maps"].size());
            for (size_t i = 0; i < count; ++i)
            {
                const auto &entry = playlist["maps"][i];
                const auto map = entry["map"].get<std::string>();
                const bool allowed = (!policy.contains("available_maps") || maps.contains(map)) &&
                                     entry["weight"].get<double>() > 0;
                weights[map] = allowed ? entry["weight"] : Json(0);
                if (allowed)
                    eligible.push_back(entry);
            }
            if (eligible.empty())
                continue;
            const auto &mode = modes.at(eligible.front()["gametype"].get<std::string>());
            Json rules = query.at("ruleset_payload"),
                 dvars = rules.value("dvar_overrides", Json::object());
            wire::require(dvars.is_object());
            // Replay applies each selected entry's game-type dvars from the same
            // published catalog. Do not pre-apply the first mode to a mixed-mode
            // playlist; that would leak one mode's rules into the next choice.
            overrides(dvars, playlist.value("dvars", Json::object()), bindings);
            assign(dvars, bindings, "online_matchmaking_use_map_weights", 1);
            if (policy.contains("minimum_players"))
            {
                const auto minimum = number(policy["minimum_players"], 200);
                wire::require(minimum > 0);
                assign(dvars, bindings, "party_minplayers", minimum);
                rules["min_slots_scale_percent"] = 0;
            }
            if (policy.contains("dvar_overrides"))
                overrides(dvars, policy["dvar_overrides"], bindings);
            wire::require(dvars.size() <= 128);
            rules["dvar_overrides"] = dvars;
            rules["map_weights"] = weights;
            rules["filter"]["playlist_id"] = id;
            rules["filter"]["playlist_version"] = version;
            PlaylistSelection selected;
            selected.rules = rules;
            if (mode.contains("teamCount"))
                selected.teamCount = number(mode["teamCount"], 200);
            selected.metadata = {{"playlist_id", id},
                                 {"playlist_version", version},
                                 {"context", playlist.value("context", std::string{})},
                                 {"eligible_entries", eligible},
                                 {"score_limit", playlist.value("score_limit", Json())},
                                 {"time_limit", playlist.value("time_limit", Json())},
                                 {"flags", playlist.value("flags", Json::array())},
                                 {"game_types", Json::object()}};
            for (const auto &entry : eligible)
                selected.metadata["game_types"][entry["gametype"].get<std::string>()] =
                    modes.at(entry["gametype"].get<std::string>());
            return selected;
        }
        return std::nullopt;
    }
} // namespace services
