#include <windows.h>
#include "tournament_services.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t maxDocument = 16383, maxCatalog = 2 * 1024 * 1024;
        constexpr uint32_t notEnrolled = 14526;

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        void persisted(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid tournament publication or persistent state");
        }

        bool boundedText(const Json &value, size_t capacity)
        {
            return value.is_string() && !value.get_ref<const std::string &>().empty() &&
                   value.get_ref<const std::string &>().size() < capacity &&
                   value.get_ref<const std::string &>().find('\0') == std::string::npos;
        }

        Json read(const std::filesystem::path &path, size_t capacity)
        {
            persisted(std::filesystem::file_size(path) <= capacity);
            std::ifstream stream(path, std::ios::binary);
            if (!stream)
                throw std::runtime_error("Tournament state read failed");
            Json result;
            stream >> result;
            persisted(result.is_object());
            return result;
        }

        void write(const std::filesystem::path &path, const Json &state)
        {
            const auto bytes = state.dump();
            persisted(bytes.size() <= maxCatalog);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("Tournament state write failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Tournament state publication failed");
        }

        std::set<uint64_t> validateBracket(const Json &state, uint64_t tournament)
        {
            // Exact Replay consumer 0x141074530: every ID indexes fixed native
            // arrays. Validate the complete bracket before emitting any string.
            persisted(
                state.is_object() && state.at("tournamentID") == tournament &&
                boundedText(state.at("tournamentStatus"), 64) &&
                (state["tournamentStatus"] == "FORMING" || state["tournamentStatus"] == "PLAYING"));
            const auto &definition = state.at("tournamentDefinition");
            persisted(definition.is_object() && definition.at("teamSize").is_number_unsigned() &&
                      definition.at("numTeams").is_number_unsigned() &&
                      definition.at("numPlayers").is_number_unsigned());
            persisted(definition["teamSize"].get<uint64_t>() <= 4 &&
                      definition["numTeams"].get<uint64_t>() <= 16);
            const auto teamSize = definition["teamSize"].get<unsigned>();
            const auto teamCount = definition["numTeams"].get<unsigned>();
            persisted(teamSize >= 1 && teamSize <= 4 && (teamCount == 8 || teamCount == 16) &&
                      definition["numPlayers"] == teamSize * teamCount);
            const auto &teams = state.at("teams");
            persisted(teams.is_array() && teams.size() == teamCount);
            std::set<uint64_t> members;
            for (unsigned index = 0; index < teamCount; ++index)
            {
                const auto &team = teams[index];
                persisted(team.is_object() && team.at("teamID") == index &&
                          team.at("playerIDs").is_array() && team["playerIDs"].size() <= teamSize);
                for (const auto &user : team["playerIDs"])
                    persisted(user.is_number_unsigned() && user.get<uint64_t>() &&
                              members.insert(user.get<uint64_t>()).second);
            }
            const auto &players = state.at("players");
            persisted(players.is_array() && players.size() == members.size());
            std::set<uint64_t> playerIds;
            for (const auto &player : players)
            {
                persisted(player.is_object() && player.at("playerID").is_number_unsigned());
                const auto user = player["playerID"].get<uint64_t>();
                persisted(members.contains(user) && playerIds.insert(user).second);
            }
            const auto &rounds = state.at("rounds");
            const unsigned roundCount = teamCount == 8 ? 3 : 4;
            persisted(rounds.is_array() && rounds.size() == roundCount);
            for (unsigned round = 0; round < roundCount; ++round)
            {
                const auto &row = rounds[round];
                persisted(row.is_object() && row.at("roundID") == round &&
                          row.at("matches").is_array() &&
                          row["matches"].size() == (teamCount >> (round + 1)));
                std::set<unsigned> participants;
                for (const auto &match : row["matches"])
                {
                    persisted(match.is_object() && match.at("teamIDs").is_array() &&
                              match["teamIDs"].size() <= 2 &&
                              match.at("readyPlayerIDs").is_array() &&
                              match["readyPlayerIDs"].size() <= 2 * teamSize &&
                              match.at("lobbyID").is_number_unsigned() &&
                              match.at("expired").is_boolean());
                    std::set<uint64_t> matchMembers;
                    std::set<uint64_t> ready;
                    for (const auto &team : match["teamIDs"])
                    {
                        persisted(team.is_number_unsigned() && team.get<uint64_t>() < teamCount &&
                                  participants.insert(team.get<unsigned>()).second);
                        for (const auto &user : teams[team.get<unsigned>()]["playerIDs"])
                            matchMembers.insert(user.get<uint64_t>());
                    }
                    for (const auto &user : match["readyPlayerIDs"])
                        persisted(user.is_number_unsigned() &&
                                  matchMembers.contains(user.get<uint64_t>()) &&
                                  ready.insert(user.get<uint64_t>()).second);
                    if (match.contains("winningTeamID"))
                    {
                        persisted(match["winningTeamID"].is_number_integer() &&
                                  match["winningTeamID"] >= -1 &&
                                  match["winningTeamID"] < teamCount);
                        const auto winner = match["winningTeamID"].get<int>();
                        persisted(winner == -1 ||
                                  std::find(match["teamIDs"].begin(),
                                            match["teamIDs"].end(),
                                            Json(winner)) != match["teamIDs"].end());
                    }
                    if (match.contains("matchResultPayload"))
                    {
                        const auto &scores = match["matchResultPayload"].at("scores");
                        persisted(scores.is_array() && scores.size() <= 2);
                        for (const auto &score : scores)
                            persisted(score.is_number_unsigned() && score.get<uint64_t>() <= 65535);
                    }
                    if (match["expired"] == true)
                        persisted(match.contains("expireReason") &&
                                  match["expireReason"].is_number_integer());
                }
            }
            persisted(state.dump().size() <= maxDocument);
            return members;
        }

        Json catalog(const std::filesystem::path &path, uint32_t title)
        {
            if (!std::filesystem::exists(path))
                return Json::array();
            auto result = read(path, maxCatalog);
            persisted(result.at("schema") == 1 && result.at("title") == title &&
                      result.at("tournaments").is_array() && result["tournaments"].size() <= 128);
            std::set<uint64_t> ids;
            std::set<std::pair<std::string, std::string>> names;
            for (const auto &row : result["tournaments"])
            {
                persisted(
                    row.is_object() && row.at("id").is_number_unsigned() &&
                    row["id"].get<uint64_t>() && ids.insert(row["id"].get<uint64_t>()).second &&
                    boundedText(row.at("name"), 128) && boundedText(row.at("data_center"), 64) &&
                    row.at("expires").is_number_unsigned() &&
                    row.at("registration_open").is_boolean() &&
                    row.at("start_search_offset_seconds").is_number() &&
                    row["start_search_offset_seconds"].get<double>() >= 0 &&
                    row["start_search_offset_seconds"].get<double>() <= 3600);
                persisted(names
                              .emplace(row["name"].get<std::string>(),
                                       row["data_center"].get<std::string>())
                              .second);
                validateBracket(row.at("state"), row["id"].get<uint64_t>());
            }
            return result["tournaments"];
        }

        Json enrollments(const std::filesystem::path &path, uint32_t title)
        {
            Json result = {{"schema", 1}, {"title", title}, {"players", Json::object()}};
            if (std::filesystem::exists(path))
                result = read(path, maxCatalog);
            persisted(result.at("schema") == 1 && result.at("title") == title &&
                      result.at("players").is_object() && result["players"].size() <= 4096);
            for (const auto &row : result["players"].items())
            {
                const auto &value = row.value();
                persisted(!row.key().empty() && row.key().size() <= 20 &&
                          row.key().find_first_not_of("0123456789") == std::string::npos &&
                          value.is_object() && value.at("id").is_number_unsigned() &&
                          value["id"].get<uint64_t>() && value.at("accepted").is_boolean() &&
                          value.at("ready").is_boolean());
            }
            return result;
        }

        const Json *published(const Json &rows, uint64_t tournament, uint64_t user)
        {
            for (const auto &row : rows)
                if (row["id"] == tournament && row["expires"].get<uint64_t>() > now() &&
                    validateBracket(row["state"], tournament).contains(user))
                    return &row;
            return nullptr;
        }

        Json stateWithReadiness(const Json &row, const Json &enrolled)
        {
            auto state = row["state"];
            // Ready-up applies to the first unfinished match for each player,
            // not future rounds. Publication remains the bracket authority.
            std::set<uint64_t> visited;
            for (auto &round : state["rounds"])
                for (auto &match : round["matches"])
                {
                    if (match["expired"] == true || match.value("winningTeamID", -1) != -1)
                        continue;
                    for (const auto &team : match["teamIDs"])
                        for (const auto &user : state["teams"][team.get<size_t>()]["playerIDs"])
                        {
                            const auto player = user.get<uint64_t>();
                            const auto key = std::to_string(player);
                            if (!visited.insert(player).second || !enrolled.contains(key))
                                continue;
                            const auto &entry = enrolled[key];
                            if (entry["id"] == row["id"] && entry["ready"] == true &&
                                std::find(match["readyPlayerIDs"].begin(),
                                          match["readyPlayerIDs"].end(),
                                          user) == match["readyPlayerIDs"].end())
                                match["readyPlayerIDs"].push_back(user);
                        }
                }
            validateBracket(state, row["id"].get<uint64_t>());
            return state;
        }
    } // namespace

    std::optional<Reply> tournamentServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &id,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &params)
    {
        if (service != 145 ||
            (task != 19 && task != 20 && task != 22 && task != 23 && task != 28 && task != 29))
            return std::nullopt;
        uint64_t tournament = 0;
        bool accepted = true;
        Json query;
        if (task == 19 || task == 23 || task == 28)
        {
            tournament = params.u64();
            wire::require(tournament != 0);
            if (task == 19)
                wire::require(params.u64() == 0xFFFFFFFFULL);
            if (task == 23)
                accepted = params.boolean();
        }
        if (task == 29)
        {
            // Replay 0x142136240 binds one bdStringResult; game registration
            // 0x1410758E0 supplies these exact two JSON keys in a 256-byte buffer.
            const auto bytes = params.text(256);
            query = Json::parse(bytes.begin(), bytes.end(), nullptr, false);
            wire::require(query.is_object() && query.contains("tournament_name") &&
                          query.contains("data_center") &&
                          boundedText(query["tournament_name"], 128) &&
                          boundedText(query["data_center"], 64) && query.size() == 2);
        }
        params.end();
        const auto root = directory / "tournaments" / std::to_string(id.titleId);
        const auto path = root / "enrollments.json";
        auto state = enrollments(path, id.titleId);
        auto &players = state["players"];
        const auto key = std::to_string(id.userId);
        if (task == 22)
        {
            if (players.erase(key))
                write(path, state);
            return Reply{0, {}, "tournament-owner-left-all"};
        }
        const auto rows = catalog(root / "catalog.json", id.titleId);
        if (task == 29)
        {
            const Json *selected = nullptr;
            for (const auto &row : rows)
                if (row["name"] == query["tournament_name"] &&
                    row["data_center"] == query["data_center"] &&
                    row["expires"].get<uint64_t>() > now() && row["registration_open"] == true)
                    selected = &row;
            if (!selected)
                return Reply{108, {}, "tournament-registration-unpublished"};
            tournament = (*selected)["id"].get<uint64_t>();
            if (!published(rows, tournament, id.userId))
                return Reply{101, {}, "tournament-participant-not-authorized"};
            if (players.contains(key) && players[key]["id"] != tournament)
                return Reply{101, {}, "tournament-conflicting-enrollment"};
            if (!players.contains(key))
            {
                if (players.size() >= 4096)
                    return Reply{108, {}, "tournament-enrollment-capacity"};
                players[key] = {{"id", tournament}, {"accepted", false}, {"ready", false}};
                write(path, state);
            }
            wire::Writer result;
            result.text(
                Json{{"start_search_offset_seconds", (*selected)["start_search_offset_seconds"]}}
                    .dump());
            return Reply{0, {std::move(result.data)}, "tournament-owner-registered"};
        }
        if (!players.contains(key))
            return Reply{notEnrolled, {}, "tournament-player-not-enrolled"};
        auto &entry = players[key];
        if (task == 20)
            tournament = entry["id"].get<uint64_t>();
        if (entry["id"] != tournament)
            return Reply{notEnrolled, {}, "tournament-owner-id-mismatch"};
        const auto *row = published(rows, tournament, id.userId);
        if (!row)
            return Reply{notEnrolled, {}, "tournament-publication-expired-or-owner-absent"};
        if (task == 20)
        {
            wire::Writer result;
            result.text(stateWithReadiness(*row, players).dump());
            return Reply{0, {std::move(result.data)}, "tournament-owner-state"};
        }
        if (task == 23 && !accepted)
            players.erase(key);
        else if (task == 23 || task == 28)
            entry["accepted"] = true;
        else if (task == 19)
            entry["ready"] = true;
        stateWithReadiness(*row, players);
        write(path, state);
        return Reply{0,
                     {},
                     task == 19   ? "tournament-owner-ready"
                     : task == 28 ? "tournament-owner-rejoined"
                     : accepted   ? "tournament-owner-join-accepted"
                                  : "tournament-owner-join-declined"};
    }
} // namespace services
