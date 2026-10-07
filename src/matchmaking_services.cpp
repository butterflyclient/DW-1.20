#include <windows.h>
#include "matchmaking_services.h"
#include "matchmaking_store.h"
#include "tournament_services.h"
#include "playlist_catalog.h"
#include "lobby.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint64_t occupiedSlots(const Json &members, const Json &slots);

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        Json read(const std::filesystem::path &path, const platform::LobbyIdentity &id)
        {
            Json state = {
                {"schema", 1}, {"title", id.titleId}, {"user", id.userId}, {"revision", 0}};
            if (std::filesystem::exists(path))
            {
                wire::require(std::filesystem::file_size(path) <= 128 * 1024);
                std::ifstream stream(path);
                if (!stream)
                    throw std::runtime_error("Matchmaker state read failed");
                stream >> state;
                wire::require(state.is_object() && state.at("schema") == 1 &&
                              state.at("title") == id.titleId && state.at("user") == id.userId &&
                              state.at("revision").is_number_unsigned());
            }
            return state;
        }

        void publish(const std::filesystem::path &path, const Json &state)
        {
            const auto bytes = state.dump();
            wire::require(bytes.size() <= 128 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("Matchmaker state persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Matchmaker state publication failed");
        }

        uint64_t randomId()
        {
            uint64_t value = 0;
            do
            {
                value = wire::at<uint64_t>(crypto::random(8), 0);
            } while (!value);
            return value;
        }

        std::string sessionFingerprint(const platform::LobbyIdentity &id)
        {
            return wire::base64Encode(crypto::sha256(id.key));
        }

        Json object(const std::string &bytes)
        {
            auto result = Json::parse(bytes.begin(), bytes.end(), nullptr, false);
            wire::require(result.is_object());
            return result;
        }

        Json loadLobby(const std::filesystem::path &path, const platform::LobbyIdentity &id)
        {
            if (std::filesystem::file_size(path) > 128 * 1024)
                throw std::runtime_error("Lobby state exceeds capacity");
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Lobby state read failed");
            Json state;
            stream >> state;
            const auto valid =
                state.is_object() && state.at("schema") == 1 && state.at("title") == id.titleId &&
                state.at("id").is_number_unsigned() && state["id"].get<uint64_t>() &&
                path.stem().string() == std::to_string(state["id"].get<uint64_t>()) &&
                state.at("owner").is_number_unsigned() && state["owner"].get<uint64_t>() &&
                state.at("expires").is_number_unsigned() &&
                state.at("update_id").is_number_unsigned() && state["update_id"].get<uint64_t>() &&
                state.at("members").is_array() && !state["members"].empty() &&
                state["members"].size() <= 200 && state.at("host_doc").is_object() &&
                state.at("backend_doc").is_object() && state["host_doc"].dump().size() < 16384 &&
                state["backend_doc"].dump().size() < 16384 &&
                state["host_doc"].at("listen_server").at("host_player_id") == state["owner"] &&
                state["host_doc"]["listen_server"].at("host_address").is_string() &&
                state["backend_doc"].at("lobby_id") == state["id"] &&
                (!state.contains("maximum_members") ||
                 (state["maximum_members"].is_number_unsigned() &&
                  state["maximum_members"].get<uint64_t>() > 0 &&
                  state["maximum_members"].get<uint64_t>() <= 200 &&
                  state["members"].size() <= state["maximum_members"].get<uint64_t>())) &&
                (!state.contains("disbanded") || state["disbanded"].is_boolean());
            if (!valid)
                throw std::runtime_error("Invalid persisted lobby layout");
            if (state.contains("host_ready") && !state["host_ready"].is_boolean())
                throw std::runtime_error("Invalid persisted host readiness");
            if (state["backend_doc"].contains("tournament"))
                matchmaking_store::validateWrite({"lobbies/" + path.filename().string(), state},
                                                 id.titleId);
            std::set<uint64_t> members;
            for (const auto &user : state["members"])
                if (!user.is_number_unsigned() || !user.get<uint64_t>() ||
                    !members.insert(user.get<uint64_t>()).second)
                    throw std::runtime_error("Invalid persisted lobby membership");
            if (!members.contains(state["owner"].get<uint64_t>()))
                throw std::runtime_error("Persisted lobby host is not a member");
            matchmaking_store::validatePendingJoins(state);
            if (state["backend_doc"].contains("player_id_to_slots"))
            {
                const auto &slots = state["backend_doc"]["player_id_to_slots"];
                if (!slots.is_object() || slots.size() > members.size())
                    throw std::runtime_error("Invalid persisted lobby reservation layout");
                for (const auto &entry : slots.items())
                    if (std::none_of(members.begin(),
                                     members.end(),
                                     [&](uint64_t user)
                                     {
                                         return entry.key() == std::to_string(user);
                                     }))
                        throw std::runtime_error("Persisted reservation has no primary member");
                if (occupiedSlots(state["members"], slots) >
                    state.value("maximum_members", uint64_t{200}))
                    throw std::runtime_error("Persisted lobby reservations exceed capacity");
            }
            return state;
        }

        bool member(const Json &lobby, uint64_t user)
        {
            return std::find(lobby.at("members").begin(), lobby.at("members").end(), Json(user)) !=
                   lobby.at("members").end();
        }

        bool hostSessionActive(const Json &state, uint32_t title)
        {
            // Unbound historical documents remain readable/disbandable, but a
            // new login cannot implicitly adopt their old native address/DTLS keys.
            if (!state.contains("owner_session"))
                return false;
            if (!state["owner_session"].is_string() ||
                state["owner_session"].get_ref<const std::string &>().size() != 44)
                throw std::runtime_error("Invalid persisted lobby host session");
            return lobby::sessionOnline(title,
                                        state.at("owner").get<uint64_t>(),
                                        state["owner_session"].get<std::string>());
        }

        void notify(Reply &reply,
                    const Json &lobby,
                    uint32_t event,
                    uint64_t mmId = 0,
                    const std::set<uint64_t> *recipients = nullptr)
        {
            const auto host = lobby.at("host_doc").dump(), backend = lobby.at("backend_doc").dump();
            wire::require(host.size() < 16384 && backend.size() < 16384);
            // Verified registered async-matchmaker decoder 0x14213F1C0. String size
            // helper 0x1420EEE60 peeks at the next typed string; no length prefix.
            wire::Writer push;
            push.u32(event);
            if (event == 2005 || event == 2001)
                push.u64(mmId);
            push.u64(lobby.at("id"));
            if (event == 2005 || event == 2006)
                push.u64(lobby.at("update_id"));
            push.text(host);
            push.text(backend);
            for (const auto &user : lobby.at("members"))
                if (!recipients || recipients->contains(user.get<uint64_t>()))
                    reply.deliveries.push_back({user.get<uint64_t>(),
                                                push.data,
                                                250,
                                                lobby.at("id").get<uint64_t>(),
                                                event == 2005 || event == 2001 ? mmId : 0});
        }

        Json searchState(const platform::LobbyIdentity &id,
                         const Json &query,
                         const Json &lobby,
                         uint64_t mmId)
        {
            return {{"schema", 1},
                    {"title", id.titleId},
                    {"user", id.userId},
                    {"revision", uint64_t{0}},
                    {"id", mmId},
                    {"lobby_id", lobby.at("id")},
                    {"query", query},
                    {"expires", lobby.at("expires")},
                    {"active", true}};
        }

        Json currentLobbies(const std::filesystem::path &root, const platform::LobbyIdentity &id)
        {
            auto shared = id;
            shared.userId = 0;
            auto index = read(root / "current-lobbies.json", shared);
            if (!index.contains("lobbies"))
                index["lobbies"] = Json::object();
            wire::require(index["lobbies"].is_object() && index["lobbies"].size() <= 4096);
            for (const auto &entry : index["lobbies"].items())
            {
                wire::require(!entry.key().empty() && entry.key().size() <= 20 &&
                              entry.key()[0] != '0' &&
                              std::all_of(entry.key().begin(),
                                          entry.key().end(),
                                          [](char c)
                                          {
                                              return c >= '0' && c <= '9';
                                          }) &&
                              entry.value().is_number_unsigned() && entry.value().get<uint64_t>());
            }
            return index;
        }

        Json prepareLobbyAssignments(const std::filesystem::path &root,
                                     const platform::LobbyIdentity &id,
                                     const Json &members,
                                     uint64_t lobbyId)
        {
            auto index = currentLobbies(root, id);
            for (const auto &user : members)
                index["lobbies"][std::to_string(user.get<uint64_t>())] = lobbyId;
            wire::require(index["lobbies"].size() <= 4096);
            const auto revision = index.at("revision").get<uint64_t>();
            wire::require(revision != UINT64_MAX);
            index["revision"] = revision + 1;
            wire::require(index.dump().size() <= 128 * 1024);
            return index;
        }

        Json requestedSlots(const Json &query)
        {
            Json slots = Json::object();
            for (const auto &user : query.at("members"))
                slots[std::to_string(user.get<uint64_t>())] = uint64_t{0};
            if (query.contains("player_id_to_slots"))
            {
                const auto &requested = query.at("player_id_to_slots");
                wire::require(requested.is_object() && requested.size() <= slots.size());
                for (const auto &entry : requested.items())
                {
                    // Replay StartMatchmaking 0x14104A450 emits one reservation
                    // when a non-primary player shares this primary's token.
                    wire::require(slots.contains(entry.key()) &&
                                  entry.value().is_number_unsigned() &&
                                  entry.value().get<uint64_t>() <= 1);
                    slots[entry.key()] = entry.value();
                }
            }
            return slots;
        }

        uint64_t occupiedSlots(const Json &members, const Json &slots)
        {
            wire::require(members.is_array() && members.size() <= 200 && slots.is_object());
            uint64_t occupied = members.size();
            for (const auto &user : members)
            {
                const auto key = std::to_string(user.get<uint64_t>());
                if (slots.contains(key))
                {
                    wire::require(slots[key].is_number_unsigned() &&
                                  slots[key].get<uint64_t>() <= 1);
                    occupied += slots[key].get<uint64_t>();
                }
            }
            return occupied;
        }

        Json lobbySlots(const Json &lobby)
        {
            // Older persisted documents predate reservation publication.
            return lobby.at("backend_doc").value("player_id_to_slots", Json::object());
        }

        bool slotsAvailable(const Json &lobby, const Json &query)
        {
            auto members = lobby.at("members");
            auto slots = lobbySlots(lobby);
            const auto requested = requestedSlots(query);
            for (const auto &entry : requested.items())
                slots[entry.key()] = entry.value();
            for (const auto &user : query.at("members"))
                if (!member(lobby, user.get<uint64_t>()))
                    members.push_back(user);
            return occupiedSlots(members, slots) <= lobby.value("maximum_members", uint64_t{200});
        }

        bool platformAllowed(const Json &query)
        {
            if (!query.contains("acceptable_platforms"))
                return true;
            const auto &platforms = query.at("acceptable_platforms");
            wire::require(platforms.is_array() && !platforms.empty() && platforms.size() <= 8);
            std::set<std::string> values;
            for (const auto &platform : platforms)
            {
                wire::require(platform.is_string());
                const auto value = platform.get<std::string>();
                wire::require(!value.empty() && value.size() <= 32 &&
                              std::all_of(value.begin(),
                                          value.end(),
                                          [](char c)
                                          {
                                              return (c >= 'a' && c <= 'z') ||
                                                     (c >= '0' && c <= '9') || c == '_';
                                          }) &&
                              values.insert(value).second);
            }
            // Original Replay GetClientPlatform 0x1410AE340 returns 2;
            // platform-string mapper 0x1410AE2F0 returns "bnet" for 2.
            // All accepted player-info/auth sessions currently belong to Replay PC.
            return values.contains("bnet");
        }

        uint64_t requestCapacity(const Json &query)
        {
            uint64_t maximum = 200;
            if (query.contains("lobby_slots"))
            {
                const auto &slots = query.at("lobby_slots");
                wire::require(slots.is_object() && slots.at("max").is_number_unsigned());
                maximum = slots.at("max").get<uint64_t>();
            }
            wire::require(maximum > 0 && maximum <= 200 &&
                          occupiedSlots(query.at("members"), requestedSlots(query)) <= maximum);
            return maximum;
        }

        Json createLobbyDocument(const platform::LobbyIdentity &id,
                                 const Json &query,
                                 const std::set<uint64_t> &users,
                                 const Json &listen,
                                 const PlaylistSelection &selection,
                                 uint64_t lobbyId,
                                 const Json &matchIds,
                                 uint64_t expires,
                                 const std::string &ownerSession)
        {
            const auto time = now();
            Json rules = selection.rules;
            Json players = Json::object(), states = Json::object(), levels = Json::object();
            for (const auto user : users)
            {
                const auto key = std::to_string(user);
                players[key] = "connected";
                states[key] = 2;
                levels[key] = "paid";
            }
            Json backend = {{"lobby_id", lobbyId},
                            {"update_id", 1},
                            {"update_time", time},
                            {"listen_server", {{"lobby_host_order", Json::array({id.userId})}}},
                            {"dtls",
                             {{"security_id", listen["security_id"]},
                              {"security_key", listen["security_key"]}}},
                            {"players", players},
                            {"player_id_to_mm_id", matchIds},
                            {"player_id_to_service_level", levels},
                            {"player_id_to_slots", requestedSlots(query)},
                            {"ruleset_payload", rules},
                            {"performance", query.value("performance", Json{{"game_type", 1}})},
                            {"team_balance",
                             {{"teams", {{"0", query["members"]}}},
                              {"squad_size", 1},
                              {"squads", Json::object()}}}};
            if (query.contains("team_balance") && query["team_balance"].contains("num_teams"))
            {
                const auto &count = query["team_balance"]["num_teams"];
                wire::require(count.is_number_unsigned() && count.get<uint64_t>() <= 200);
                for (uint64_t team = 1; team < count.get<uint64_t>(); ++team)
                    backend["team_balance"]["teams"][std::to_string(team)] = Json::array();
            }
            if (selection.splitPartiesForTeamBalance)
            {
                auto &teams = backend["team_balance"]["teams"];
                if (!query.contains("team_balance") || !query["team_balance"].contains("num_teams"))
                    for (unsigned i = 1; i < selection.teamCount; ++i)
                        teams[std::to_string(i)] = Json::array();
                // Local low-population policy may separate a searching party.
                // Native Replay ReadyTeams compares the actual assigned teams;
                // two friends on one TDM team otherwise cannot start a 1v1.
                for (auto &team : teams)
                    team = Json::array();
                for (const auto &user : query.at("members"))
                {
                    auto destination = teams.begin();
                    for (auto team = teams.begin(); team != teams.end(); ++team)
                        if (occupiedSlots(team.value(), backend["player_id_to_slots"]) <
                            occupiedSlots(destination.value(), backend["player_id_to_slots"]))
                            destination = team;
                    destination.value().push_back(user);
                }
            }
            if (query.contains("private_lobby"))
                backend["private_lobby"] = query["private_lobby"];
            Json host = {
                {"listen_server",
                 {{"host_player_id", id.userId}, {"host_address", listen["local_address"]}}},
                {"player_state", states},
                {"ruleset_payload", {{"is_merge_src", false}, {"is_merge_dst", false}}},
                {"lobby_open", true},
                {"lobby_open_for_pres_join", true},
                {"team_balance", {{"can_change_teams", true}}},
                {"update_id", uint64_t{1}},
                {"update_time", time},
                {"game_state", {{"state", "intermission"}}}};
            Json lobby = {{"schema", 1},
                          {"title", id.titleId},
                          {"id", lobbyId},
                          {"owner", id.userId},
                          {"owner_session", ownerSession},
                          {"host_ready", false},
                          {"members", query["members"]},
                          {"update_id", uint64_t{1}},
                          {"expires", expires},
                          {"host_doc", host},
                          {"backend_doc", backend},
                          {"query_constraints",
                           {{"acceptable_platforms",
                             query.value("acceptable_platforms", Json::array({"bnet"}))}}},
                          {"match_selection", selection.metadata}};
            lobby["maximum_members"] = requestCapacity(query);
            wire::require(lobby["host_doc"].dump().size() < 16384 &&
                          lobby["backend_doc"].dump().size() < 16384);
            return lobby;
        }

        uint64_t nextDocumentTime(const Json &lobby)
        {
            uint64_t previous = 0;
            for (const auto *document : {&lobby.at("host_doc"), &lobby.at("backend_doc")})
            {
                if (document->contains("update_time"))
                {
                    const auto &time = document->at("update_time");
                    wire::require(time.is_number_unsigned());
                    previous = std::max(previous, time.get<uint64_t>());
                }
            }
            wire::require(previous != UINT64_MAX);
            // Replay UpdateLobbyDocument 0x14104C6D0 drops equal timestamps,
            // even with a newer update ID. Several commits can share one second.
            return std::max(now(), previous + 1);
        }

        void eraseUsers(Json &array, const std::set<uint64_t> &users)
        {
            wire::require(array.is_array() && array.size() <= 200);
            for (const auto &user : array)
                wire::require(user.is_number_unsigned() && user.get<uint64_t>());
            array.erase(std::remove_if(array.begin(),
                                       array.end(),
                                       [&](const Json &user)
                                       {
                                           return users.contains(user.get<uint64_t>());
                                       }),
                        array.end());
        }

        std::vector<matchmaking_store::Write> reconcileMembers(const std::filesystem::path &root,
                                                               const platform::LobbyIdentity &id,
                                                               Json &lobby,
                                                               Json &host)
        {
            const auto owner = std::to_string(id.userId);
            wire::require(host.at("player_state").contains(owner) &&
                          host.at("player_state").at(owner).get<uint64_t>() < 4);
            std::set<uint64_t> removed;
            // Replay UpdateHostDoc 0x14104BFA0 sends the complete primary-player
            // snapshot and omits member status 4 (eREADY_TO_REMOVE). A present
            // status 3 (eWONT_CONNECT) remains acknowledged until that omission.
            for (const auto &user : lobby.at("members"))
            {
                const auto key = std::to_string(user.get<uint64_t>());
                if (!host.at("player_state").contains(key) || host["player_state"][key] == 4)
                    removed.insert(user.get<uint64_t>());
            }
            if (removed.empty())
                return {};
            wire::require(!removed.contains(id.userId));
            auto &backend = lobby.at("backend_doc");
            std::set<uint64_t> searches;
            for (const auto user : removed)
            {
                const auto key = std::to_string(user);
                searches.insert(backend.at("player_id_to_mm_id").at(key).get<uint64_t>());
                host["player_state"].erase(key);
                for (const char *field : {"players",
                                          "player_id_to_mm_id",
                                          "player_id_to_service_level",
                                          "player_id_to_performance",
                                          "player_id_to_slots"})
                {
                    if (backend.contains(field))
                    {
                        wire::require(backend.at(field).is_object());
                        backend[field].erase(key);
                    }
                }
            }
            eraseUsers(lobby["members"], removed);
            eraseUsers(backend["listen_server"]["lobby_host_order"], removed);
            // Replay ParseTeamInfo consumes both teams and squads as objects of
            // UInt64 arrays. Remove every assignment, retaining empty team slots.
            for (const char *field : {"teams", "squads"})
            {
                auto &groups = backend.at("team_balance").at(field);
                wire::require(groups.is_object() && groups.size() <= 200);
                for (auto &group : groups)
                    eraseUsers(group, removed);
            }
            std::vector<matchmaking_store::Write> writes;
            for (const auto &value : backend.at("player_id_to_mm_id"))
                searches.erase(value.get<uint64_t>());
            for (const auto searchId : searches)
            {
                const auto name = "searches/" + std::to_string(searchId) + ".json";
                const auto path = root / name;
                if (!std::filesystem::exists(path))
                    continue;
                wire::require(std::filesystem::file_size(path) <= 128 * 1024);
                std::ifstream stream(path);
                Json search;
                if (!stream || !(stream >> search))
                    throw std::runtime_error("Removed member search read failed");
                wire::require(search.at("schema") == 1 && search.at("title") == id.titleId &&
                              search.at("id") == searchId &&
                              search.at("lobby_id") == lobby.at("id") &&
                              search.at("active").is_boolean());
                if (search.at("active") != false)
                {
                    search["active"] = false;
                    writes.push_back({name, std::move(search)});
                }
            }
            auto assignments = currentLobbies(root, id);
            bool changed = false;
            for (const auto user : removed)
            {
                const auto key = std::to_string(user);
                if (assignments["lobbies"].contains(key) &&
                    assignments["lobbies"][key] == lobby.at("id"))
                {
                    assignments["lobbies"].erase(key);
                    changed = true;
                }
            }
            if (changed)
            {
                const auto revision = assignments.at("revision").get<uint64_t>();
                wire::require(revision != UINT64_MAX);
                assignments["revision"] = revision + 1;
                writes.push_back({"current-lobbies.json", std::move(assignments)});
            }
            return writes;
        }

        Json publicPool(const Json &query, const PlaylistSelection &selection)
        {
            auto rules = selection.rules;
            // This is a search instruction, not a different match ruleset.
            rules.erase("only_join_existing_lobbies");
            // JIP is an admission preference, not an intermission ruleset.
            // Native solo/party searches can disagree on it in the same playlist.
            rules.erase("join_in_progress");
            Json pool = {{"rules", rules},
                    {"dedicated_server", query.value("dedicated_server", Json::object())},
                    {"performance", query.value("performance", Json{{"game_type", 1}})},
                    {"team_balance", query.value("team_balance", Json::object())},
                    {"maximum_members", requestCapacity(query)}};
            if (selection.splitPartiesForTeamBalance)
                pool["split_parties_for_team_balance"] = true;
            return pool;
        }

        Reply assignMembers(const std::filesystem::path &directory,
                            const platform::LobbyIdentity &id,
                            const Json &query,
                            const std::set<uint64_t> &users,
                            Json lobby,
                            const char *operation)
        {
            const auto root = directory / "matchmaking" / std::to_string(id.titleId);
            uint64_t mmId = 0;
            do
            {
                mmId = randomId();
            } while (std::filesystem::exists(root / "searches" / (std::to_string(mmId) + ".json")));
            const auto revision = lobby.at("update_id").get<uint64_t>();
            wire::require(revision != UINT64_MAX);
            const auto documentTime = nextDocumentTime(lobby);
            lobby["expires"] = std::min(lobby.at("expires").get<uint64_t>(), id.expires);
            lobby["update_id"] = revision + 1;
            for (auto *document : {&lobby["host_doc"], &lobby["backend_doc"]})
            {
                (*document)["update_id"] = revision + 1;
                (*document)["update_time"] = documentTime;
            }
            auto &backend = lobby["backend_doc"];
            auto reservations = lobbySlots(lobby);
            const auto requested = requestedSlots(query);
            for (const auto &entry : requested.items())
                reservations[entry.key()] = entry.value();
            backend["player_id_to_slots"] = reservations;
            auto &teams = backend["team_balance"]["teams"];
            wire::require(teams.is_object() && !teams.empty());
            auto team = teams.begin();
            for (auto it = teams.begin(); it != teams.end(); ++it)
            {
                wire::require(it.value().is_array());
                if (occupiedSlots(it.value(), reservations) <
                    occupiedSlots(team.value(), reservations))
                    team = it;
            }
            std::set<uint64_t> existing;
            for (const auto &user : lobby.at("members"))
                existing.insert(user.get<uint64_t>());
            for (const auto user : users)
            {
                const auto key = std::to_string(user);
                if (existing.insert(user).second)
                {
                    lobby["members"].push_back(user);
                    lobby["host_doc"]["player_state"][key] = 2;
                    backend["players"][key] = "connected";
                    backend["player_id_to_service_level"][key] = "paid";
                    backend["listen_server"]["lobby_host_order"].push_back(user);
                    if (lobby.value("match_selection", Json::object())
                             .value("split_parties_for_team_balance", false))
                    {
                        // Existing members retain their assignments. Balance
                        // each new primary together with its reserved guests.
                        team = teams.begin();
                        for (auto destination = teams.begin(); destination != teams.end();
                             ++destination)
                            if (occupiedSlots(destination.value(), reservations) <
                                occupiedSlots(team.value(), reservations))
                                team = destination;
                    }
                    // The normal policy keeps a joining party on one team.
                    team.value().push_back(user);
                }
                backend["player_id_to_mm_id"][key] = mmId;
            }
            wire::require(lobby["host_doc"].dump().size() < 16384 && backend.dump().size() < 16384);
            const auto lobbyId = lobby.at("id").get<uint64_t>();
            const bool hostReady = lobby.value("host_ready", true);
            if (!hostReady)
            {
                auto &pending = lobby["pending_join_members"];
                if (pending.is_null())
                    pending = Json::array();
                for (const auto user : users)
                    if (user != lobby.at("owner").get<uint64_t>() &&
                        std::find(pending.begin(), pending.end(), Json(user)) == pending.end())
                        pending.push_back(user);
            }
            const auto assignments =
                prepareLobbyAssignments(root, id, lobby.at("members"), lobbyId);
            const std::array<matchmaking_store::Write, 3> writes = {
                matchmaking_store::Write{"lobbies/" + std::to_string(lobbyId) + ".json", lobby},
                matchmaking_store::Write{"searches/" + std::to_string(mmId) + ".json",
                                         searchState(id, query, lobby, mmId)},
                matchmaking_store::Write{"current-lobbies.json", assignments}};
            matchmaking_store::commit(root, id.titleId, writes);
            wire::Writer result;
            result.text(Json{{"mm_id", mmId}}.dump());
            Reply reply{0, {std::move(result.data)}, operation};
            if (hostReady)
                notify(reply, lobby, 2001, mmId, &users);
            std::set<uint64_t> observers;
            for (const auto user : existing)
                if (!users.contains(user))
                    observers.insert(user);
            notify(reply, lobby, 2006, 0, &observers);
            return reply;
        }

        std::optional<Reply> publicJoin(const std::filesystem::path &directory,
                                        const platform::LobbyIdentity &id,
                                        const Json &query,
                                        const std::set<uint64_t> &users)
        {
            if (query.contains("private_lobby"))
                return std::nullopt;
            const auto root = directory / "matchmaking" / std::to_string(id.titleId);
            const auto index = currentLobbies(root, id);
            const auto &rules = query.at("ruleset_payload");
            const bool inProgress = rules.value("join_in_progress", false);
            std::set<uint64_t> ids;
            std::vector<Json> candidates;
            // The bounded current-assignment index excludes abandoned historical
            // files and duplicates. No directory-wide scan grows with every search.
            for (const auto &value : index.at("lobbies"))
            {
                const auto lobbyId = value.get<uint64_t>();
                if (!ids.insert(lobbyId).second)
                    continue;
                const auto path = root / "lobbies" / (std::to_string(lobbyId) + ".json");
                if (!std::filesystem::exists(path))
                    continue;
                auto candidate = loadLobby(path, id);
                const auto compatible = selectPlaylist(
                    directory, id.titleId, query, {},
                    candidate.at("match_selection").at("playlist_id").get<unsigned>());
                if (!compatible)
                    continue;
                const auto ownerKey = std::to_string(candidate.at("owner").get<uint64_t>());
                const auto &host = candidate.at("host_doc");
                const auto &backend = candidate.at("backend_doc");
                if (!candidate.contains("public_pool") ||
                    candidate["public_pool"] != publicPool(query, *compatible) ||
                    backend.contains("private_lobby") || !index.at("lobbies").contains(ownerKey) ||
                    index.at("lobbies").at(ownerKey) != lobbyId ||
                    candidate.at("match_selection") != compatible->metadata ||
                    candidate.value("disbanded", false) ||
                    candidate.at("expires").get<uint64_t>() <= now() ||
                    !host.value("lobby_open", false) || !hostSessionActive(candidate, id.titleId) ||
                    !platformAllowed(candidate.value("query_constraints", Json::object())) ||
                    !slotsAvailable(candidate, query) ||
                    std::any_of(users.begin(),
                                users.end(),
                                [&](uint64_t user)
                                {
                                    return member(candidate, user);
                                }))
                    continue;
                const auto state = host.at("game_state").value("state", std::string{});
                // Replay's accepted initial host snapshots use an empty state
                // while waiting for players. They are open pre-game lobbies;
                // the owner/session/capacity checks above still apply.
                if (!state.empty() && state != "intermission" && !(inProgress && state == "in_game"))
                    continue;
                candidates.push_back(std::move(candidate));
            }
            std::sort(candidates.begin(),
                      candidates.end(),
                      [](const Json &a, const Json &b)
                      {
                          const auto aSlots = occupiedSlots(a.at("members"), lobbySlots(a));
                          const auto bSlots = occupiedSlots(b.at("members"), lobbySlots(b));
                          if (aSlots != bSlots)
                              return aSlots > bSlots;
                          return a.at("id").get<uint64_t>() < b.at("id").get<uint64_t>();
                      });
            if (candidates.empty())
                return std::nullopt;
            return assignMembers(directory,
                                 id,
                                 query,
                                 users,
                                 std::move(candidates.front()),
                                 "matchmaker-public-join-assigned");
        }

        Reply presenceJoin(const std::filesystem::path &directory,
                           const platform::LobbyIdentity &id,
                           const Json &query,
                           const std::set<uint64_t> &users)
        {
            // Replay's own StartMatchmaking 14104A450 emits one of these
            // fields instead of a playlist filter. The SDK event-2001 reader
            // at 14213F1C0 binds mmID/lobbyID/host doc/backend doc.
            const bool byLobby = query.contains("lobby_id_to_presence_join");
            const auto target =
                query.at(byLobby ? "lobby_id_to_presence_join" : "player_id_to_presence_join");
            wire::require(target.is_number_unsigned() && target.get<uint64_t>() &&
                          target.get<uint64_t>() != UINT64_MAX &&
                          !(byLobby && query.contains("player_id_to_presence_join")));
            if (!byLobby && !lobby::online(id.titleId, target.get<uint64_t>()))
                return {108, {}, "matchmaker-presence-player-offline"};
            const auto root = directory / "matchmaking" / std::to_string(id.titleId);
            const auto lobbies = root / "lobbies";
            std::vector<std::filesystem::path> candidates;
            if (byLobby)
                candidates.push_back(lobbies / (std::to_string(target.get<uint64_t>()) + ".json"));
            else
            {
                const auto index = currentLobbies(root, id);
                const auto key = std::to_string(target.get<uint64_t>());
                if (index["lobbies"].contains(key))
                    candidates.push_back(
                        lobbies /
                        (std::to_string(index["lobbies"][key].get<uint64_t>()) + ".json"));
            }
            for (const auto &path : candidates)
            {
                if (!std::filesystem::exists(path))
                    continue;
                auto lobby = loadLobby(path, id);
                if ((!byLobby && !member(lobby, target.get<uint64_t>())) ||
                    !hostSessionActive(lobby, id.titleId) || lobby.value("disbanded", false) ||
                    lobby.at("expires").get<uint64_t>() <= now())
                    continue;
                const auto &host = lobby.at("host_doc");
                if (!host.value("lobby_open_for_pres_join", false))
                    continue;
                if (!platformAllowed(lobby.value("query_constraints", Json::object())) ||
                    !slotsAvailable(lobby, query))
                    continue;
                // Recheck the installed-map/playlist publication. A presence
                // join must not revive a lobby whose packages/version are gone.
                const auto selection = selectPlaylist(
                    directory,
                    id.titleId,
                    Json{{"ruleset_payload", lobby["backend_doc"]["ruleset_payload"]}});
                if (!selection || selection->metadata.at("eligible_entries") !=
                                      lobby.at("match_selection").at("eligible_entries"))
                    continue;
                return assignMembers(directory,
                                     id,
                                     query,
                                     users,
                                     std::move(lobby),
                                     "matchmaker-presence-join-assigned");
            }
            return {108, {}, "matchmaker-presence-lobby-unavailable"};
        }

        std::optional<Reply> lobbyServices(const std::filesystem::path &directory,
                                           const platform::LobbyIdentity &id,
                                           uint8_t task,
                                           wire::Reader &p)
        {
            const auto root = directory / "matchmaking" / std::to_string(id.titleId);
            if (task == 18)
            {
                const auto query = object(p.text(16384));
                p.end();
                wire::require(query.contains("members") && query["members"].is_array() &&
                              !query["members"].empty() && query["members"].size() <= 200 &&
                              query.contains("tokens") && query["tokens"].is_array() &&
                              query["tokens"].size() == query["members"].size());
                const auto time = now();
                std::set<uint64_t> users;
                Json hostInfo;
                for (size_t i = 0; i < query["members"].size(); ++i)
                {
                    wire::require(query["members"][i].is_number_unsigned() &&
                                  query["tokens"][i].is_number_unsigned());
                    const auto user = query["members"][i].get<uint64_t>(),
                               token = query["tokens"][i].get<uint64_t>();
                    wire::require(user && token && users.insert(user).second);
                    auto identity = id;
                    identity.userId = user;
                    const auto path = root / "players" / (std::to_string(user) + ".json");
                    if (!std::filesystem::exists(path))
                        return Reply{14507, {}, "matchmaker-member-token-missing"};
                    const auto state = read(path, identity);
                    if (state.value("token", uint64_t{}) != token ||
                        state.value("token_expires", uint64_t{}) <= time)
                        return Reply{14507, {}, "matchmaker-member-token-invalid"};
                    const auto session = state.value("token_session", std::string{});
                    // A party token grants membership only while its issuing
                    // authenticated session is live. The owner must use this
                    // request's own session, not another login for the same ID.
                    if ((user == id.userId && session != sessionFingerprint(id)) ||
                        !lobby::sessionOnline(id.titleId, user, session))
                        return Reply{14507, {}, "matchmaker-member-token-session-expired"};
                    if (user == id.userId)
                        hostInfo = state.at("info");
                }
                if (!users.contains(id.userId))
                    return Reply{101, {}, "matchmaker-request-owner-denied"};
                (void)requestCapacity(query);
                if (!platformAllowed(query))
                    return Reply{108, {}, "matchmaker-platform-unavailable"};
                if (auto tournament = startTournamentSearch(directory, id, query))
                    return tournament;
                if (query.contains("lobby_id_to_presence_join") ||
                    query.contains("player_id_to_presence_join"))
                    return presenceJoin(directory, id, query, users);
                const auto &listen = hostInfo.at("listen_server");
                // The 84-byte native address and 8/16-byte DTLS keys come from Replay's
                // player-info registration. Never invent an unreachable host endpoint.
                wire::require(
                    listen.contains("local_address") && listen["local_address"].is_string() &&
                    listen["local_address"].get<std::string>().size() == 112 &&
                    listen.contains("security_id") && listen["security_id"].is_string() &&
                    listen["security_id"].get<std::string>().size() == 12 &&
                    listen.contains("security_key") && listen["security_key"].is_string() &&
                    listen["security_key"].get<std::string>().size() == 24);
                wire::require(
                    wire::base64(listen["local_address"].get<std::string>(), 84).size() == 84 &&
                    wire::base64(listen["security_id"].get<std::string>(), 8).size() == 8 &&
                    wire::base64(listen["security_key"].get<std::string>(), 16).size() == 16);
                const auto selection = selectPlaylist(directory, id.titleId, query);
                if (!selection)
                    return Reply{108, {}, "matchmaker-playlist-or-map-unavailable"};
                if (auto joined = publicJoin(directory, id, query, users))
                    return joined;
                if (query.at("ruleset_payload").value("only_join_existing_lobbies", false))
                    return Reply{108, {}, "matchmaker-public-lobby-unavailable"};
                uint64_t mmId = 0;
                do
                {
                    mmId = randomId();
                } while (
                    std::filesystem::exists(root / "searches" / (std::to_string(mmId) + ".json")));
                uint64_t lobbyId = 0;
                do
                {
                    lobbyId = randomId();
                } while (std::filesystem::exists(root / "lobbies" /
                                                 (std::to_string(lobbyId) + ".json")));
                Json matchIds = Json::object();
                for (const auto user : users)
                    matchIds[std::to_string(user)] = mmId;
                auto lobby = createLobbyDocument(id,
                                                 query,
                                                 users,
                                                 listen,
                                                 *selection,
                                                 lobbyId,
                                                 matchIds,
                                                 std::min(time + 3600, id.expires),
                                                 sessionFingerprint(id));
                if (!query.contains("private_lobby"))
                    lobby["public_pool"] = publicPool(query, *selection);
                auto pendingMembers = query.at("members");
                eraseUsers(pendingMembers, {id.userId});
                if (!pendingMembers.empty())
                    lobby["pending_join_members"] = pendingMembers;
                const auto assignments =
                    prepareLobbyAssignments(root, id, lobby.at("members"), lobbyId);
                const std::array<matchmaking_store::Write, 3> writes = {
                    matchmaking_store::Write{"lobbies/" + std::to_string(lobbyId) + ".json", lobby},
                    matchmaking_store::Write{"searches/" + std::to_string(mmId) + ".json",
                                             searchState(id, query, lobby, mmId)},
                    matchmaking_store::Write{"current-lobbies.json", assignments}};
                matchmaking_store::commit(root, id.titleId, writes);
                wire::Writer result;
                result.text(Json{{"mm_id", mmId}}.dump());
                Reply reply{0, {std::move(result.data)}, "matchmaker-search-created"};
                // Replay's CreateNewLobby accepts only the searching host's
                // state. Other party members enter through JoinLobby instead.
                const std::set<uint64_t> creator{id.userId};
                notify(reply, lobby, 2005, mmId, &creator);
                // The first accepted host document acknowledges that Replay's
                // CreateLobby callback installed the new native DTLS session.
                // Sending JoinLobby here lets a faster peer connect before that
                // key is registered, failing native PartyAtomic connectivity.
                return reply;
            }
            if (task == 8 || task == 9)
            {
                const auto mmId = p.u64();
                p.end();
                wire::require(mmId != 0);
                const auto path = root / "searches" / (std::to_string(mmId) + ".json");
                if (!std::filesystem::exists(path))
                    return Reply{108, {}, "matchmaker-search-not-found"};
                auto state = read(path, id);
                if (state.value("expires", uint64_t{}) <= now())
                    return Reply{108, {}, "matchmaker-search-expired"};
                state["active"] = false;
                const std::array<matchmaking_store::Write, 1> writes = {
                    matchmaking_store::Write{"searches/" + path.filename().string(), state}};
                matchmaking_store::commit(root, id.titleId, writes);
                wire::Writer result;
                result.boolean(true);
                return Reply{0,
                             {std::move(result.data)},
                             task == 8 ? "matchmaker-search-cancelled"
                                       : "matchmaker-search-shutdown"};
            }
            if (task == 10)
            {
                // Native RunLobbyDisband 0x141048DE0 calls 0x140F73DF0 /
                // 0x142135BF0: one lobby UInt64, with no bound result object.
                const auto lobbyId = p.u64();
                p.end();
                wire::require(lobbyId != 0);
                const auto path = root / "lobbies" / (std::to_string(lobbyId) + ".json");
                if (!std::filesystem::exists(path))
                    return Reply{108, {}, "matchmaker-lobby-not-found"};
                auto lobby = loadLobby(path, id);
                if (lobby.at("owner") != id.userId)
                    return Reply{101, {}, "matchmaker-disband-owner-denied"};
                const bool already = lobby.value("disbanded", false);
                std::vector<matchmaking_store::Write> writes;
                if (!already)
                {
                    lobby["disbanded"] = true;
                    lobby["disbanded_at"] = now();
                    lobby["host_doc"]["lobby_open"] = false;
                    lobby["host_doc"]["lobby_open_for_pres_join"] = false;
                    writes.push_back({"lobbies/" + path.filename().string(), lobby});
                }
                std::set<uint64_t> searches;
                for (const auto &value : lobby["backend_doc"]["player_id_to_mm_id"])
                {
                    if (!searches.insert(value.get<uint64_t>()).second)
                        continue;
                    const auto searchPath =
                        root / "searches" / (std::to_string(value.get<uint64_t>()) + ".json");
                    if (!std::filesystem::exists(searchPath))
                        continue;
                    // Disband is restricted to the original host. Member searches may
                    // have different owners after a later join, so load by file data.
                    wire::require(std::filesystem::file_size(searchPath) <= 128 * 1024);
                    std::ifstream stream(searchPath);
                    if (!stream)
                        throw std::runtime_error("Lobby search read failed");
                    Json search;
                    stream >> search;
                    stream.close();
                    wire::require(search.at("schema") == 1 && search.at("title") == id.titleId &&
                                  search.at("lobby_id") == lobbyId);
                    if (search.at("active") != false)
                    {
                        search["active"] = false;
                        writes.push_back({"searches/" + searchPath.filename().string(), search});
                    }
                }
                auto assignments = currentLobbies(root, id);
                bool indexChanged = false;
                for (const auto &user : lobby.at("members"))
                {
                    const auto key = std::to_string(user.get<uint64_t>());
                    if (assignments["lobbies"].contains(key) &&
                        assignments["lobbies"][key] == lobbyId)
                    {
                        assignments["lobbies"].erase(key);
                        indexChanged = true;
                    }
                }
                if (indexChanged)
                {
                    const auto revision = assignments.at("revision").get<uint64_t>();
                    wire::require(revision != UINT64_MAX);
                    assignments["revision"] = revision + 1;
                    writes.push_back({"current-lobbies.json", assignments});
                }
                if (!writes.empty())
                    matchmaking_store::commit(root, id.titleId, writes);
                if (already)
                    return Reply{0, {}, "matchmaker-lobby-already-disbanded"};
                wire::Writer push;
                push.u32(2002);
                push.u64(lobbyId);
                push.u64(0);
                Reply reply{0, {}, "matchmaker-lobby-disbanded"};
                for (const auto &user : lobby.at("members"))
                    reply.deliveries.push_back({user.get<uint64_t>(), push.data, 250});
                return reply;
            }
            if (task == 13 || task == 15)
            {
                const auto lobbyId = p.u64();
                wire::require(lobbyId != 0);
                uint64_t update = 0;
                Json host;
                if (task == 15)
                {
                    update = p.u64();
                    host = object(p.text(16384));
                }
                p.end();
                const auto path = root / "lobbies" / (std::to_string(lobbyId) + ".json");
                if (!std::filesystem::exists(path))
                    return Reply{108, {}, "matchmaker-lobby-not-found"};
                auto lobby = loadLobby(path, id);
                if (!member(lobby, id.userId))
                    return Reply{101, {}, "matchmaker-lobby-member-denied"};
                if (lobby.value("disbanded", false))
                    return Reply{108, {}, "matchmaker-lobby-disbanded"};
                if (lobby.at("expires").get<uint64_t>() <= now())
                    return Reply{108, {}, "matchmaker-lobby-expired"};
                if (task == 13)
                {
                    // Bound bdLobbyDocuments result supplies host string then backend.
                    wire::Writer result;
                    result.text(lobby.at("host_doc").dump());
                    result.text(lobby.at("backend_doc").dump());
                    return Reply{0, {std::move(result.data)}, "matchmaker-lobby-documents-read"};
                }
                const bool migration = lobby.at("owner") != id.userId;
                std::string address;
                if (migration)
                {
                    // Replay PostMigrationBecomeHost 0x141046BC0 fetches the
                    // existing documents. UpdatedLobbyDocumentsBecomeHost
                    // 0x14104DBD0 retains their DTLS keys and sets its own UID
                    // and native address before UpdateHostDoc 0x14104BFA0.
                    // The party elects its host; this service validates its claim.
                    if (hostSessionActive(lobby, id.titleId))
                        return Reply{101, {}, "matchmaker-host-update-owner-denied"};
                    const auto assignments = currentLobbies(root, id);
                    const auto key = std::to_string(id.userId);
                    if (!assignments["lobbies"].contains(key) ||
                        assignments["lobbies"][key] != lobbyId)
                        return Reply{108, {}, "matchmaker-migration-assignment-expired"};
                    const auto playerPath = root / "players" / (key + ".json");
                    if (!std::filesystem::exists(playerPath))
                        return Reply{108, {}, "matchmaker-migration-token-missing"};
                    const auto player = read(playerPath, id);
                    if (player.value("token_expires", uint64_t{}) <= now() ||
                        player.value("token_session", std::string{}) != sessionFingerprint(id) ||
                        !lobby::sessionOnline(id.titleId, id.userId, sessionFingerprint(id)))
                        return Reply{108, {}, "matchmaker-migration-session-expired"};
                    const auto searchId =
                        lobby["backend_doc"]["player_id_to_mm_id"].at(key).get<uint64_t>();
                    const auto searchPath =
                        root / "searches" / (std::to_string(searchId) + ".json");
                    if (!std::filesystem::exists(searchPath) ||
                        std::filesystem::file_size(searchPath) > 128 * 1024)
                        return Reply{108, {}, "matchmaker-migration-search-expired"};
                    std::ifstream stream(searchPath);
                    Json search;
                    if (!stream || !(stream >> search))
                        throw std::runtime_error("Migration search read failed");
                    wire::require(search.at("schema") == 1 && search.at("title") == id.titleId &&
                                  search.at("id") == searchId && search.at("lobby_id") == lobbyId);
                    if (!search.value("active", false) ||
                        search.at("expires").get<uint64_t>() <= now())
                        return Reply{108, {}, "matchmaker-migration-search-expired"};
                    const auto &query = search.at("query");
                    wire::require(query.at("members").is_array() && query.at("tokens").is_array() &&
                                  query["members"].size() == query["tokens"].size() &&
                                  query["members"].size() <= 200);
                    bool bound = false;
                    for (size_t i = 0; i < query["members"].size(); ++i)
                        if (query["members"][i] == id.userId &&
                            query["tokens"][i] == player.at("token"))
                            bound = true;
                    if (!bound)
                        return Reply{108, {}, "matchmaker-migration-membership-session-expired"};
                    address = player.at("info")
                                  .at("listen_server")
                                  .at("local_address")
                                  .get<std::string>();
                    wire::require(address.size() == 112 && wire::base64(address, 84).size() == 84);
                }
                else
                {
                    if (!hostSessionActive(lobby, id.titleId) ||
                        lobby.at("owner_session") != sessionFingerprint(id))
                        return Reply{108, {}, "matchmaker-host-update-session-expired"};
                    address = lobby["host_doc"]["listen_server"]["host_address"].get<std::string>();
                }
                wire::require(
                    host.contains("listen_server") && host["listen_server"].is_object() &&
                    host["listen_server"].value("host_player_id", uint64_t{}) == id.userId &&
                    host["listen_server"].value("host_address", std::string{}) == address &&
                    host.contains("player_state") && host["player_state"].is_object() &&
                    host["player_state"].size() <= 200 && host.contains("ruleset_payload") &&
                    host["ruleset_payload"].is_object() && host.contains("team_balance") &&
                    host["team_balance"].is_object() &&
                    host["team_balance"].contains("can_change_teams") &&
                    host["team_balance"]["can_change_teams"].is_boolean());
                const auto revision = lobby.at("update_id").get<uint64_t>();
                wire::Writer result;
                result.boolean(update == revision);
                Reply reply{0, {std::move(result.data)}, "matchmaker-host-update-conflict"};
                if (update != revision)
                    return reply;
                for (auto it = host["player_state"].begin(); it != host["player_state"].end(); ++it)
                {
                    wire::require(it.value().is_number_unsigned() &&
                                  it.value().get<uint64_t>() <= 4);
                    wire::require(lobby["backend_doc"]["players"].contains(it.key()));
                }
                wire::require(revision != UINT64_MAX);
                const auto documentTime = nextDocumentTime(lobby);
                if (migration)
                {
                    lobby["owner"] = id.userId;
                    lobby["owner_session"] = sessionFingerprint(id);
                    auto &order = lobby["backend_doc"]["listen_server"]["lobby_host_order"];
                    wire::require(order.is_array() && order.size() <= 200);
                    eraseUsers(order, {id.userId});
                    order.insert(order.begin(), id.userId);
                }
                auto writes = reconcileMembers(root, id, lobby, host);
                lobby["update_id"] = revision + 1;
                host["update_id"] = revision + 1;
                host["update_time"] = documentTime;
                lobby["host_doc"] = host;
                lobby["host_ready"] = true;
                lobby["backend_doc"]["update_id"] = revision + 1;
                lobby["backend_doc"]["update_time"] = documentTime;
                std::set<uint64_t> joiningMembers;
                if (lobby.contains("pending_join_members"))
                {
                    for (const auto &user : lobby.at("pending_join_members"))
                        if (user.get<uint64_t>() != id.userId &&
                            member(lobby, user.get<uint64_t>()))
                            joiningMembers.insert(user.get<uint64_t>());
                    lobby.erase("pending_join_members");
                }
                writes.insert(writes.begin(), {"lobbies/" + path.filename().string(), lobby});
                matchmaking_store::commit(root, id.titleId, writes);
                reply.operation = migration ? "matchmaker-lobby-host-migrated"
                                            : "matchmaker-host-document-updated";
                for (const auto user : joiningMembers)
                {
                    const std::set<uint64_t> recipient{user};
                    const auto mmId = lobby.at("backend_doc").at("player_id_to_mm_id")
                                          .at(std::to_string(user)).get<uint64_t>();
                    notify(reply, lobby, 2001, mmId, &recipient);
                }
                std::set<uint64_t> observers;
                for (const auto &user : lobby.at("members"))
                    if (!joiningMembers.contains(user.get<uint64_t>()))
                        observers.insert(user.get<uint64_t>());
                notify(reply, lobby, 2006, 0, &observers);
                return reply;
            }
            return std::nullopt;
        }
    } // namespace

    std::optional<TournamentLobbyPlan> prepareTournamentRoundLobby(
        const std::filesystem::path &directory,
        uint32_t title,
        uint64_t tournament,
        unsigned round,
        unsigned match,
        const Json &teams,
        const std::vector<Json> &searches,
        const Json &roundQuery,
        uint64_t expires,
        const std::string &requiredMap)
    {
        wire::require(tournament && round < 4 && match < 8 && teams.is_array() &&
                      teams.size() == 2 && !searches.empty() && searches.size() <= 8);
        const auto root = directory / "matchmaking" / std::to_string(title);
        Json query = roundQuery, matchIds = Json::object(), sessions = Json::object();
        query["members"] = Json::array();
        query["player_id_to_slots"] = Json::object();
        std::set<uint64_t> users, searchIds;
        const auto index = currentLobbies(root, platform::LobbyIdentity{.titleId = title});
        Json hostPlayer;
        platform::LobbyIdentity owner;
        owner.titleId = title;
        expires = std::min(expires, now() + 3600);
        for (const auto &search : searches)
        {
            const auto searchId = search.at("id").get<uint64_t>();
            matchmaking_store::validateWrite(
                {"searches/" + std::to_string(searchId) + ".json", search}, title);
            wire::require(search.at("tournament_id") == tournament &&
                          searchIds.insert(searchId).second);
            expires = std::min(expires, search.at("expires").get<uint64_t>());
            for (size_t position = 0; position < search["query"]["members"].size(); ++position)
            {
                const auto user = search["query"]["members"][position].get<uint64_t>();
                const auto key = std::to_string(user);
                wire::require(users.insert(user).second);
                platform::LobbyIdentity identity;
                identity.titleId = title;
                identity.userId = user;
                const auto player = read(root / "players" / (key + ".json"), identity);
                const auto session = search.at("member_sessions").at(key).get<std::string>();
                if (!lobby::sessionOnline(title, user, session) ||
                    player.value("token_session", std::string{}) != session ||
                    !player.contains("token") ||
                    player["token"] != search["query"]["tokens"][position] ||
                    player.value("token_expires", uint64_t{}) <= now())
                    return std::nullopt;
                if (index["lobbies"].contains(key))
                {
                    const auto previousPath =
                        root / "lobbies" /
                        (std::to_string(index["lobbies"][key].get<uint64_t>()) + ".json");
                    if (std::filesystem::exists(previousPath))
                    {
                        const auto previous = loadLobby(previousPath, identity);
                        if (!previous.value("disbanded", false) &&
                            previous["expires"].get<uint64_t>() > now() &&
                            hostSessionActive(previous, title) &&
                            (!previous["backend_doc"].contains("tournament") ||
                             previous["backend_doc"]["tournament"]["tournament_id"] != tournament ||
                             previous["backend_doc"]["tournament"]["round_id"].get<unsigned>() >=
                                 round))
                            return std::nullopt;
                    }
                }
                expires = std::min(expires, player["token_expires"].get<uint64_t>());
                sessions[key] = session;
                matchIds[key] = searchId;
                query["members"].push_back(user);
                const auto slots = requestedSlots(search["query"]);
                query["player_id_to_slots"][key] = slots[key];
                if (!owner.userId && user == search["user"] && player.contains("info") &&
                    player["info"]["listen_server"].contains("local_address") &&
                    player["info"]["listen_server"].contains("security_id") &&
                    player["info"]["listen_server"].contains("security_key"))
                {
                    owner.userId = user;
                    hostPlayer = player;
                }
            }
        }
        if (!owner.userId || expires <= now())
            return std::nullopt;
        std::set<uint64_t> assigned;
        Json nativeTeams = Json::object();
        for (size_t side = 0; side < teams.size(); ++side)
        {
            const auto &team = teams[side];
            wire::require(team.at("teamID").is_number_unsigned() &&
                          team["teamID"].get<uint64_t>() < 16 && team.at("playerIDs").is_array() &&
                          !team["playerIDs"].empty() && team["playerIDs"].size() <= 4);
            nativeTeams[std::to_string(side)] = team["playerIDs"];
            for (const auto &user : team["playerIDs"])
                wire::require(user.is_number_unsigned() &&
                              assigned.insert(user.get<uint64_t>()).second);
        }
        wire::require(assigned == users);
        query["lobby_slots"] = {{"max", users.size()}};
        query["team_balance"] = {{"num_teams", uint64_t{2}}};
        const auto selection = selectPlaylist(directory, title, query, requiredMap);
        if (!selection)
            return std::nullopt;
        const auto &listen = hostPlayer.at("info").at("listen_server");
        if (!listen.contains("local_address") || !listen.contains("security_id") ||
            !listen.contains("security_key"))
            return std::nullopt;
        wire::require(wire::base64(listen.at("local_address").get<std::string>(), 84).size() ==
                          84 &&
                      wire::base64(listen.at("security_id").get<std::string>(), 8).size() == 8 &&
                      wire::base64(listen.at("security_key").get<std::string>(), 16).size() == 16);
        uint64_t lobbyId = 0;
        do
        {
            lobbyId = randomId();
        } while (std::filesystem::exists(root / "lobbies" / (std::to_string(lobbyId) + ".json")));
        auto state = createLobbyDocument(owner,
                                         query,
                                         users,
                                         listen,
                                         *selection,
                                         lobbyId,
                                         matchIds,
                                         expires,
                                         sessions[std::to_string(owner.userId)].get<std::string>());
        auto &backend = state["backend_doc"];
        backend["team_balance"]["teams"] = nativeTeams;
        backend["tournament"] = {{"tournament_id", tournament},
                                 {"lobby_to_tournament_team_ids",
                                  {{"0", teams[0]["teamID"]}, {"1", teams[1]["teamID"]}}},
                                 {"round_id", round}};
        state["host_doc"]["team_balance"]["can_change_teams"] = false;
        // A tournament match is a closed allocation, never a public/presence pool.
        state["host_doc"]["lobby_open_for_pres_join"] = false;
        TournamentLobbyPlan plan;
        plan.lobbyId = lobbyId;
        plan.writes.push_back({"lobbies/" + std::to_string(lobbyId) + ".json", state});
        for (auto search : searches)
        {
            search["lobby_id"] = lobbyId;
            search["round_id"] = round;
            search["match_id"] = match;
            search["expires"] = expires;
            search["active"] = true;
            plan.writes.push_back(
                {"searches/" + std::to_string(search["id"].get<uint64_t>()) + ".json", search});
        }
        plan.writes.push_back({"current-lobbies.json",
                               prepareLobbyAssignments(root, owner, query["members"], lobbyId)});
        return plan;
    }

    std::optional<Delivery> tournamentRoundLobbyDelivery(const std::filesystem::path &directory,
                                                         uint32_t title,
                                                         uint64_t user,
                                                         uint64_t tournament,
                                                         uint64_t lobbyId,
                                                         const Json &metadata)
    {
        platform::LobbyIdentity identity;
        identity.titleId = title;
        identity.userId = user;
        const auto root = directory / "matchmaking" / std::to_string(title);
        const auto path = root / "lobbies" / (std::to_string(lobbyId) + ".json");
        if (!std::filesystem::exists(path))
            return std::nullopt;
        const auto state = loadLobby(path, identity);
        if (!member(state, user) || !state["backend_doc"].contains("tournament") ||
            state["backend_doc"]["tournament"] != metadata || state.value("disbanded", false) ||
            state["expires"].get<uint64_t>() <= now() || !hostSessionActive(state, title))
            return std::nullopt;
        const auto search =
            state["backend_doc"]["player_id_to_mm_id"].at(std::to_string(user)).get<uint64_t>();
        Reply reply;
        const std::set<uint64_t> recipient{user};
        // Native create/join envelopes retain the allocated party's mmID.
        notify(reply, state, state["owner"] == user ? 2005 : 2001, search, &recipient);
        auto delivery = reply.deliveries.at(0);
        const auto bytes = Json::array({state["host_doc"], state["backend_doc"]}).dump();
        delivery.tournamentId = tournament;
        delivery.tournamentRoundLobby = true;
        delivery.tournamentStateHash = wire::base64Encode(
            crypto::sha256({reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()}));
        delivery.delayMs = 750;
        return delivery;
    }

    uint32_t matchmakingHostAuthorized(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &id,
                                       uint64_t lobbyId,
                                       std::span<const uint64_t> participants)
    {
        const auto root = directory / "matchmaking" / std::to_string(id.titleId);
        matchmaking_store::recover(root, id.titleId);
        const auto path = root / "lobbies" / (std::to_string(lobbyId) + ".json");
        if (!std::filesystem::exists(path))
            return 108;
        const auto lobby = loadLobby(path, id);
        if (lobby.value("disbanded", false) || lobby["expires"].get<uint64_t>() <= now())
            return 108;
        if (lobby["owner"] != id.userId || !member(lobby, id.userId))
            return 101;
        if (!hostSessionActive(lobby, id.titleId) ||
            lobby.at("owner_session") != wire::base64Encode(crypto::sha256(id.key)))
            return 108;
        for (const auto user : participants)
            if (!member(lobby, user))
                return 101;
        return 0;
    }

    std::optional<platform::LobbyIdentity> matchmakingReportIdentity(
        const std::filesystem::path &directory,
        const platform::LobbyIdentity &sender,
        uint64_t participant)
    {
        if (participant == sender.userId)
            return sender;
        const auto root = directory / "matchmaking" / std::to_string(sender.titleId);
        const auto index = currentLobbies(root, sender);
        const auto owner = std::to_string(sender.userId), user = std::to_string(participant);
        const auto &assignments = index.at("lobbies");
        if (!assignments.contains(owner) || !assignments.contains(user) ||
            assignments.at(owner) != assignments.at(user))
            return std::nullopt;
        const std::array<uint64_t, 1> users{participant};
        if (matchmakingHostAuthorized(directory, sender,
                                     assignments.at(owner).get<uint64_t>(), users) != 0)
            return std::nullopt;
        // Native listen hosts submit match events for their remote members.
        // Validate their first-party claims against that member's live signed
        // identity, never against an arbitrary client-supplied account.
        return lobby::onlineIdentity(sender.titleId, participant);
    }

    bool matchmakingDeliveryValid(const std::filesystem::path &directory,
                                  uint32_t title,
                                  const Delivery &delivery)
    {
        if (!delivery.lobbyId)
            return true;
        const auto root = directory / "matchmaking" / std::to_string(title);
        matchmaking_store::recover(root, title);
        const auto path = root / "lobbies" / (std::to_string(delivery.lobbyId) + ".json");
        if (!std::filesystem::exists(path))
            return false;
        platform::LobbyIdentity id;
        id.titleId = title;
        const auto lobby = loadLobby(path, id);
        if (!hostSessionActive(lobby, title) || lobby.value("disbanded", false) ||
            lobby.at("expires").get<uint64_t>() <= now() || !member(lobby, delivery.user))
            return false;
        if (delivery.searchId)
        {
            const auto key = std::to_string(delivery.user);
            const auto &assignments = lobby.at("backend_doc").at("player_id_to_mm_id");
            if (!assignments.contains(key) || assignments.at(key) != delivery.searchId)
                return false;
            const auto searchPath =
                root / "searches" / (std::to_string(delivery.searchId) + ".json");
            if (!std::filesystem::exists(searchPath) ||
                std::filesystem::file_size(searchPath) > 128 * 1024)
                return false;
            std::ifstream stream(searchPath);
            Json search;
            stream >> search;
            if (delivery.tournamentRoundLobby)
            {
                matchmaking_store::validateWrite(
                    {"searches/" + std::to_string(delivery.searchId) + ".json", search}, title);
                const auto index = currentLobbies(root, id);
                if (!index["lobbies"].contains(key) || index["lobbies"][key] != delivery.lobbyId ||
                    search.at("tournament_id") != delivery.tournamentId)
                    return false;
                id.userId = delivery.user;
                const auto player = read(root / "players" / (key + ".json"), id);
                const auto &session = search.at("member_sessions").at(key);
                if (!lobby::sessionOnline(title, delivery.user, session.get<std::string>()) ||
                    player.at("token_session") != session ||
                    player.at("token_expires").get<uint64_t>() <= now())
                    return false;
                bool tokenMatches = false;
                for (size_t position = 0; position < search["query"]["members"].size(); ++position)
                    if (search["query"]["members"][position] == delivery.user)
                        tokenMatches = player.at("token") == search["query"]["tokens"][position];
                if (!tokenMatches)
                    return false;
            }
            return search.at("schema") == 1 && search.at("title") == title &&
                   search.at("lobby_id") == delivery.lobbyId && search.value("active", false) &&
                   search.at("expires").get<uint64_t>() > now();
        }
        return true;
    }

    std::optional<Reply> matchmakingServices(const std::filesystem::path &directory,
                                             const platform::LobbyIdentity &id,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &p)
    {
        if (service != 145)
            return std::nullopt;
        matchmaking_store::recover(directory / "matchmaking" / std::to_string(id.titleId),
                                   id.titleId);
        if (auto reply = lobbyServices(directory, id, task, p))
            return reply;
        if (task != 2 && task != 3)
            return std::nullopt;
        const auto path = directory / "matchmaking" / std::to_string(id.titleId) / "players" /
                          (std::to_string(id.userId) + ".json");
        auto state = read(path, id);
        if (task == 2)
        {
            // Replay 0x142136420 calls 0x142156130, which uses writeString,
            // not writeBlob. The caller passes strlen+1 as the string capacity.
            // The native JSON buffer is 0x10000 bytes; there is no result binding.
            const auto bytes = p.text(65536);
            p.end();
            Json info;
            try
            {
                info = Json::parse(bytes.begin(), bytes.end());
            }
            catch (const Json::exception &)
            {
                wire::require(false);
            }
            wire::require(info.is_object() && info.contains("dedicated_server") &&
                          info["dedicated_server"].is_object() && info.contains("listen_server") &&
                          info["listen_server"].is_object() && info.contains("game_state") &&
                          info["game_state"].is_object() && info.contains("hardware") &&
                          info["hardware"].is_string() && info["hardware"] == "pc");
            if (!state.contains("info") || state["info"] != info)
            {
                const auto revision = state.at("revision").get<uint64_t>();
                wire::require(revision != UINT64_MAX);
                state["revision"] = revision + 1;
                state["info"] = info;
                state["updated"] = now();
                publish(path, state);
            }
            return Reply{0, {}, "matchmaker-player-info-persisted"};
        }
        // Replay 0x142135730 has no parameters and binds one UInt64 result.
        // Native 0x141042C00/0x14104B0D0 keep this token and use it to register
        // the authenticated player in later matchmaking operations.
        p.end();
        if (!state.contains("info"))
            return Reply{108, {}, "matchmaker-player-info-required"};
        const auto time = now();
        const auto session = sessionFingerprint(id);
        if (!state.contains("token") || state.value("token_expires", uint64_t{}) <= time ||
            state.value("token_session", std::string{}) != session)
        {
            uint64_t token = 0;
            do
            {
                const auto random = crypto::random(8);
                token = wire::at<uint64_t>(random, 0);
            } while (!token);
            state["token"] = token;
            state["token_expires"] = std::min(time + 3600, id.expires);
            state["token_session"] = session;
            publish(path, state);
        }
        const auto token = state.at("token").get<uint64_t>();
        wire::require(token != 0);
        wire::Writer result;
        result.u64(token);
        return Reply{0, {std::move(result.data)}, "matchmaker-account-token-issued"};
    }
} // namespace services
