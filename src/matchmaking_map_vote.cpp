#include "host_os.h"
#include "matchmaking_map_vote.h"
#include "lobby.h"
#include "playlist_catalog.h"
#include "matchmaking_store.h"
#include "wire.h"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <fstream>
#include <map>
#include <set>

namespace services::map_vote
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr uint64_t voteMilliseconds = 30000;
        uint64_t clockMilliseconds()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        }
        uint64_t userId(const std::string &key)
        {
            uint64_t user = 0;
            const auto parsed = std::from_chars(key.data(), key.data() + key.size(), user);
            wire::require(parsed.ec == std::errc{} && parsed.ptr == key.data() + key.size() &&
                          user && std::to_string(user) == key);
            return user;
        }
        Json choices(const std::filesystem::path &directory, const Json &lobby, unsigned entry)
        {
            const auto path = directory / "playlists" / lobby.at("title").dump() / "catalog.json";
            wire::require(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
            std::ifstream stream(path);
            Json catalog;
            stream >> catalog;
            const auto playlist = lobby.at("match_selection").at("playlist_id").get<unsigned>();
            const auto &eligible = lobby.at("match_selection").at("eligible_entries");
            for (const auto &candidate : catalog.at("playlists"))
            {
                if (candidate.at("playlist") != playlist)
                    continue;
                const auto &entries = candidate.at("maps");
                wire::require(entry < entries.size() && entry < 20);
                const auto mode = entries.at(entry).at("gametype");
                Json result = Json::array();
                std::set<std::string> maps;
                for (size_t index = 0; index < std::min<size_t>(20, entries.size()); ++index)
                {
                    const auto &value = entries[index];
                    if (value.at("gametype") != mode ||
                        std::find(eligible.begin(), eligible.end(), value) == eligible.end() ||
                        !maps.insert(value.at("map").get<std::string>()).second)
                        continue;
                    result.push_back({{"entry", static_cast<unsigned>(index)},
                                      {"map", value.at("map")}, {"gametype", mode}});
                    if (result.size() == 3)
                        break;
                }
                wire::require(!result.empty());
                return result;
            }
            wire::require(false);
            return Json::array();
        }
        Json counts(const Json &ballot)
        {
            Json result = Json::array({uint64_t{0}, uint64_t{0}, uint64_t{0}});
            for (const auto &vote : ballot.at("votes"))
            {
                const auto choice = vote.get<unsigned>();
                wire::require(choice > 0 && choice <= ballot.at("choices").size());
                result[choice - 1] = result[choice - 1].get<uint64_t>() + 1;
            }
            return result;
        }
        std::set<uint64_t> allocatedHumans(const std::filesystem::path &directory, const Json &lobby)
        {
            const auto root = directory / "matchmaking" / lobby.at("title").dump();
            std::ifstream stream(root / "current-lobbies.json");
            Json index;
            stream >> index;
            matchmaking_store::validateWrite({"current-lobbies.json", index}, lobby.at("title"));
            std::map<uint64_t, Json> searches;
            std::set<uint64_t> result;
            const auto title = lobby.at("title").get<uint32_t>();
            const auto time = clockMilliseconds() / 1000;
            for (const auto &member : lobby.at("members"))
            {
                const auto user = member.get<uint64_t>();
                const auto key = std::to_string(user);
                if (!index.at("lobbies").contains(key) || index["lobbies"][key] != lobby.at("id"))
                    continue;
                const auto searchId = lobby.at("backend_doc").at("player_id_to_mm_id").at(key).get<uint64_t>();
                auto found = searches.find(searchId);
                if (found == searches.end())
                {
                    const auto path = root / "searches" / (std::to_string(searchId) + ".json");
                    if (!std::filesystem::exists(path))
                        continue;
                    wire::require(std::filesystem::file_size(path) <= 128 * 1024);
                    std::ifstream searchStream(path);
                    Json search;
                    searchStream >> search;
                    matchmaking_store::validateWrite({"searches/" + path.filename().string(), search}, title);
                    found = searches.emplace(searchId, std::move(search)).first;
                }
                const auto &search = found->second;
                if (search.at("lobby_id") != lobby.at("id") || !search.at("active").get<bool>() ||
                    search.at("expires").get<uint64_t>() <= time ||
                    !search.contains("member_sessions") || !search["member_sessions"].contains(key))
                    continue;
                if (lobby::sessionOnline(title, user, search["member_sessions"][key].get<std::string>()))
                    result.insert(user);
            }
            return result;
        }
    }

    bool pending(const Json &lobby)
    {
        return lobby.value("map_vote_enabled", false) &&
               (!lobby.contains("map_vote") || !lobby.at("map_vote").at("complete").get<bool>());
    }

    void update(const std::filesystem::path &directory, const platform::LobbyIdentity &identity,
                Json &lobby, Json &host)
    {
        const auto oldPhase = lobby.at("host_doc").value("game_state", Json::object())
                                  .value("state", std::string{});
        const auto phase = host.value("game_state", Json::object()).value("state", std::string{});
        const bool supplied = host.contains("dw_map_vote");
        if (!supplied && !lobby.contains("map_vote") && !lobby.value("map_vote_enabled", false))
            return;
        if ((oldPhase == "in_game" || oldPhase == "countdown") &&
            (phase.empty() || phase == "intermission"))
        {
            const auto cycle = lobby.value("map_vote_cycle", uint64_t{0});
            wire::require(cycle < uint64_t{INT32_MAX});
            lobby["map_vote_cycle"] = cycle + 1;
            if (lobby.contains("map_vote"))
                lobby["backend_doc"]["ruleset_payload"]["map_weights"] =
                    lobby.at("map_vote").at("original_weights");
            lobby.erase("map_vote");
            // The next accepted native host snapshot arms the new round.
            host.erase("dw_map_vote");
            return;
        }
        if (!supplied && !lobby.contains("map_vote"))
            return; // Explicit client handshake keeps existing clients unchanged.
        Json request;
        if (supplied)
        {
            request = host.at("dw_map_vote");
            wire::require(request.is_object() && request.at("version") == 1 &&
                          request.at("entry").is_number_unsigned() &&
                          request.at("entry").get<unsigned>() < 20 &&
                          request.at("votes").is_object() && request["votes"].size() <= 200);
            host.erase("dw_map_vote");
        }
        if (!lobby.contains("map_vote"))
        {
            if (!supplied || lobby.at("backend_doc").contains("private_lobby") ||
                lobby.at("backend_doc").contains("tournament"))
                return;
            wire::require(phase.empty() || phase == "intermission");
            const auto started = lobby.value("auto_fill_started_ms", clockMilliseconds());
            lobby["map_vote_enabled"] = true;
            lobby["map_vote"] = {{"version", 1},
                                 {"cycle", lobby.value("map_vote_cycle", uint64_t{0})},
                                 {"started_ms", started}, {"complete", false},
                                 {"remaining_ms", voteMilliseconds},
                                 {"winner", uint64_t{0}}, {"votes", Json::object()},
                                 {"original_weights", lobby.at("backend_doc").at("ruleset_payload").at("map_weights")},
                                 {"choices", choices(directory, lobby, request.at("entry"))}};
        }
        auto &ballot = lobby.at("map_vote");
        if (ballot.at("complete").get<bool>())
            return; // Late votes cannot change the launch map or frozen tally.
        wire::require(phase.empty() || phase == "intermission");
        const auto humans = allocatedHumans(directory, lobby);
        Json retained = Json::object();
        for (const auto &vote : ballot.at("votes").items())
            if (host.at("player_state").contains(vote.key()) &&
                host.at("player_state").at(vote.key()) == 2 &&
                humans.contains(userId(vote.key())))
                retained[vote.key()] = vote.value();
        ballot["votes"] = std::move(retained);
        if (supplied)
        {
            Json votes = Json::object();
            for (const auto &vote : request.at("votes").items())
            {
                const auto user = userId(vote.key());
                wire::require(vote.value().is_number_unsigned() &&
                              vote.value().get<unsigned>() > 0 &&
                              vote.value().get<unsigned>() <= ballot.at("choices").size());
                // The native host supplies its already replicated human votes.
                // Only connected retained primary accounts can contribute.
                if (std::find(lobby.at("members").begin(), lobby.at("members").end(), Json(user)) ==
                        lobby.at("members").end() ||
                    !host.at("player_state").contains(vote.key()) ||
                    host.at("player_state").at(vote.key()) != 2 ||
                    !humans.contains(user))
                    continue;
                votes[vote.key()] = vote.value();
            }
            ballot["votes"] = std::move(votes);
        }
        const auto time = clockMilliseconds(), started = ballot.at("started_ms").get<uint64_t>();
        const auto elapsed = time >= started ? time - started : 0;
        ballot["remaining_ms"] = voteMilliseconds - std::min(voteMilliseconds, elapsed);
        if (ballot.at("choices").size() == 1 || (time >= started && time - started >= voteMilliseconds))
        {
            const auto latest = selectPlaylist(directory, identity.titleId,
                Json{{"ruleset_payload", lobby.at("backend_doc").at("ruleset_payload")}}, {},
                lobby.at("match_selection").at("playlist_id").get<unsigned>());
            wire::require(latest.has_value());
            for (const auto &choice : ballot.at("choices"))
                wire::require(std::any_of(latest->metadata.at("eligible_entries").begin(),
                    latest->metadata.at("eligible_entries").end(), [&](const Json &entry)
                    { return entry.at("map") == choice.at("map") &&
                             entry.at("gametype") == choice.at("gametype"); }));
            const auto tally = counts(ballot);
            unsigned winner = 0;
            for (unsigned choice = 1; choice < ballot.at("choices").size(); ++choice)
                if (tally[choice] > tally[winner])
                    winner = choice; // Equal votes retain the first published choice.
            ballot["winner"] = winner;
            ballot["complete"] = true;
            ballot["remaining_ms"] = uint64_t{0};
            ballot["frozen_ms"] = time;
            auto &weights = lobby["backend_doc"]["ruleset_payload"]["map_weights"];
            const auto selected = ballot.at("choices")[winner].at("map").get<std::string>();
            for (auto &weight : weights.items())
                weight.value() = weight.key() == selected ? 1 : 0;
        }
    }

    void publish(const Json &lobby, Json &overrides)
    {
        if (!lobby.value("map_vote_enabled", false))
            return;
        overrides["replay_dw_mapVoteActive"] = lobby.contains("map_vote") ? 1 : 0;
        overrides["replay_dw_mapVoteComplete"] = !pending(lobby) ? 1 : 0;
        overrides["replay_dw_mapVoteCycle"] = lobby.value("map_vote_cycle", uint64_t{0});
        overrides["replay_dw_mapVoteRemainingMs"] = uint64_t{0};
        overrides["replay_dw_mapVoteChoiceCount"] = uint64_t{0};
        overrides["replay_dw_mapVoteWinner"] = uint64_t{0};
        const auto lobbyId = lobby.at("id").get<uint64_t>();
        for (unsigned part = 0; part < 4; ++part)
            overrides["replay_dw_mapVoteLobby" + std::to_string(part)] = (lobbyId >> (part * 16)) & 65535;
        const char *entries[] = {"replay_dw_mapVoteEntryA", "replay_dw_mapVoteEntryB", "replay_dw_mapVoteEntryC"};
        const char *votes[] = {"replay_dw_mapVoteVotesA", "replay_dw_mapVoteVotesB", "replay_dw_mapVoteVotesC"};
        for (unsigned choice = 0; choice < 3; ++choice)
        {
            overrides[entries[choice]] = 0;
            overrides[votes[choice]] = 0;
        }
        if (!lobby.contains("map_vote"))
            return;
        const auto &ballot = lobby.at("map_vote");
        const auto tally = counts(ballot);
        overrides["replay_dw_mapVoteChoiceCount"] = ballot.at("choices").size();
        overrides["replay_dw_mapVoteWinner"] = ballot.at("winner");
        overrides["replay_dw_mapVoteRemainingMs"] = ballot.at("remaining_ms");
        for (unsigned choice = 0; choice < ballot.at("choices").size(); ++choice)
        {
            overrides[entries[choice]] = ballot.at("choices")[choice].at("entry");
            overrides[votes[choice]] = tally[choice];
        }
    }

    void validate(const Json &lobby)
    {
        if (lobby.contains("map_vote_enabled"))
            wire::require(lobby["map_vote_enabled"].is_boolean());
        if (lobby.contains("map_vote_cycle"))
            wire::require(lobby["map_vote_cycle"].is_number_unsigned() &&
                          lobby["map_vote_cycle"].get<uint64_t>() <= INT32_MAX);
        if (!lobby.contains("map_vote"))
            return;
        const auto &ballot = lobby.at("map_vote");
        wire::require(ballot.is_object() && ballot.at("version") == 1 &&
                      ballot.at("cycle") == lobby.value("map_vote_cycle", uint64_t{0}) &&
                      ballot.at("started_ms").is_number_unsigned() &&
                      ballot.at("remaining_ms").is_number_unsigned() &&
                      ballot["remaining_ms"].get<uint64_t>() <= voteMilliseconds &&
                      ballot.at("original_weights").is_object() &&
                      ballot.at("complete").is_boolean() && ballot.at("choices").is_array() &&
                      !ballot["choices"].empty() && ballot["choices"].size() <= 3 &&
                      ballot.at("winner").is_number_unsigned() &&
                      ballot["winner"].get<unsigned>() < ballot["choices"].size() &&
                      ballot.at("votes").is_object() && ballot["votes"].size() <= 200);
        std::set<std::string> maps;
        const auto &original = ballot.at("original_weights");
        const auto &current = lobby.at("backend_doc").at("ruleset_payload").at("map_weights");
        wire::require(current.is_object() && original.size() == current.size());
        for (const auto &weight : original.items())
            wire::require(current.contains(weight.key()) && weight.value().is_number() &&
                          std::isfinite(weight.value().get<double>()) && weight.value().get<double>() >= 0);
        if (ballot.at("complete").get<bool>())
            wire::require(ballot.at("frozen_ms").is_number_unsigned() &&
                          ballot["frozen_ms"].get<uint64_t>() >= ballot["started_ms"].get<uint64_t>() &&
                          ballot["remaining_ms"] == 0);
        else
            wire::require(!ballot.contains("frozen_ms") && original == current);
        const auto mode = ballot["choices"][0].at("gametype");
        for (const auto &choice : ballot.at("choices"))
        {
            wire::require(choice.at("entry").is_number_unsigned() && choice["entry"].get<unsigned>() < 20 &&
                          choice.at("gametype") == mode && choice.at("map").is_string() &&
                          maps.insert(choice["map"].get<std::string>()).second);
            wire::require(original.contains(choice["map"].get<std::string>()) &&
                          original.at(choice["map"].get<std::string>()).get<double>() > 0);
            const auto &eligible = lobby.at("match_selection").at("eligible_entries");
            wire::require(std::any_of(eligible.begin(), eligible.end(), [&](const Json &entry)
                { return entry.at("map") == choice.at("map") && entry.at("gametype") == mode; }));
        }
        (void)counts(ballot);
        for (const auto &vote : ballot.at("votes").items())
        {
            const auto user = userId(vote.key());
            wire::require(ballot.at("complete").get<bool>() ||
                          std::find(lobby.at("members").begin(), lobby.at("members").end(), Json(user)) !=
                              lobby.at("members").end());
        }
    }
}
