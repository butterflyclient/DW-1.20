#include <windows.h>
#include "matchmaking_services.h"
#include "playlist_catalog.h"
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
            const auto hash = crypto::sha256(id.key);
            std::string result;
            result.reserve(hash.size() * 2);
            for (const auto byte : hash)
            {
                result.push_back("0123456789abcdef"[byte >> 4]);
                result.push_back("0123456789abcdef"[byte & 15]);
            }
            return result;
        }

        Json object(const std::string &bytes)
        {
            auto result = Json::parse(bytes.begin(), bytes.end(), nullptr, false);
            wire::require(result.is_object());
            return result;
        }

        Json loadLobby(const std::filesystem::path &path, const platform::LobbyIdentity &id)
        {
            wire::require(std::filesystem::file_size(path) <= 128 * 1024);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Lobby state read failed");
            Json state;
            stream >> state;
            wire::require(state.at("schema") == 1 && state.at("title") == id.titleId &&
                          state.at("members").is_array() && state["members"].size() <= 200);
            return state;
        }

        bool member(const Json &lobby, uint64_t user)
        {
            return std::find(lobby.at("members").begin(), lobby.at("members").end(), Json(user)) !=
                   lobby.at("members").end();
        }

        void notify(Reply &reply, const Json &lobby, uint32_t event, uint64_t mmId = 0)
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
                reply.deliveries.push_back({user.get<uint64_t>(),
                                            push.data,
                                            250,
                                            lobby.at("id").get<uint64_t>(),
                                            event == 2005 ? mmId : 0});
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
                    if (user == id.userId)
                        hostInfo = state.at("info");
                }
                if (!users.contains(id.userId))
                    return Reply{101, {}, "matchmaker-request-owner-denied"};
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
                const auto mmId = randomId();
                uint64_t lobbyId = 0;
                do
                {
                    lobbyId = randomId();
                } while (std::filesystem::exists(root / "lobbies" /
                                                 (std::to_string(lobbyId) + ".json")));
                const auto selection = selectPlaylist(directory, id.titleId, query);
                if (!selection)
                    return Reply{108, {}, "matchmaker-playlist-or-map-unavailable"};
                Json rules = selection->rules;
                Json players = Json::object(), states = Json::object(), matchIds = Json::object(),
                     levels = Json::object();
                for (const auto user : users)
                {
                    const auto key = std::to_string(user);
                    players[key] = "connected";
                    states[key] = 2;
                    matchIds[key] = mmId;
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
                                {"ruleset_payload", rules},
                                {"performance", query.value("performance", Json{{"game_type", 1}})},
                                {"team_balance",
                                 {{"teams", {{"0", query["members"]}}},
                                  {"squad_size", 1},
                                  {"squads", Json::object()}}}};
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
                    {"game_state", {{"state", "intermission"}}}};
                Json lobby = {{"schema", 1},
                              {"title", id.titleId},
                              {"id", lobbyId},
                              {"owner", id.userId},
                              {"members", query["members"]},
                              {"update_id", 1},
                              {"expires", std::min(time + 3600, id.expires)},
                              {"host_doc", host},
                              {"backend_doc", backend},
                              {"match_selection", selection->metadata}};
                wire::require(host.dump().size() < 16384 && backend.dump().size() < 16384);
                publish(root / "lobbies" / (std::to_string(lobbyId) + ".json"), lobby);
                publish(root / "searches" / (std::to_string(mmId) + ".json"),
                        {{"schema", 1},
                         {"title", id.titleId},
                         {"user", id.userId},
                         {"revision", 0},
                         {"id", mmId},
                         {"lobby_id", lobbyId},
                         {"query", query},
                         {"expires", lobby["expires"]},
                         {"active", true}});
                wire::Writer result;
                result.text(Json{{"mm_id", mmId}}.dump());
                Reply reply{0, {std::move(result.data)}, "matchmaker-search-created"};
                notify(reply, lobby, 2005, mmId);
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
                publish(path, state);
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
                if (!already)
                {
                    lobby["disbanded"] = true;
                    lobby["disbanded_at"] = now();
                    lobby["host_doc"]["lobby_open"] = false;
                    lobby["host_doc"]["lobby_open_for_pres_join"] = false;
                    publish(path, lobby);
                }
                for (const auto &value : lobby["backend_doc"]["player_id_to_mm_id"])
                {
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
                    search["active"] = false;
                    publish(searchPath, search);
                }
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
                if (lobby.at("owner") != id.userId)
                    return Reply{101, {}, "matchmaker-host-update-owner-denied"};
                wire::require(
                    host.contains("listen_server") && host["listen_server"].is_object() &&
                    host["listen_server"].value("host_player_id", uint64_t{}) == id.userId &&
                    host["listen_server"].value("host_address", std::string{}) ==
                        lobby["host_doc"]["listen_server"]["host_address"].get<std::string>() &&
                    host.contains("player_state") && host["player_state"].is_object() &&
                    host["player_state"].size() <= 200 && host.contains("ruleset_payload") &&
                    host["ruleset_payload"].is_object() && host.contains("team_balance") &&
                    host["team_balance"].is_object() &&
                    host["team_balance"].contains("can_change_teams") &&
                    host["team_balance"]["can_change_teams"].is_boolean());
                for (auto it = host["player_state"].begin(); it != host["player_state"].end(); ++it)
                {
                    wire::require(it.value().is_number_unsigned() &&
                                  it.value().get<uint64_t>() <= 4);
                    wire::require(lobby["backend_doc"]["players"].contains(it.key()));
                }
                const auto revision = lobby.at("update_id").get<uint64_t>();
                wire::Writer result;
                result.boolean(update == revision);
                Reply reply{0, {std::move(result.data)}, "matchmaker-host-update-conflict"};
                if (update != revision)
                    return reply;
                wire::require(revision != UINT64_MAX);
                lobby["update_id"] = revision + 1;
                host["update_id"] = revision + 1;
                host["update_time"] = now();
                lobby["host_doc"] = host;
                lobby["backend_doc"]["update_id"] = revision + 1;
                lobby["backend_doc"]["update_time"] = now();
                publish(path, lobby);
                reply.operation = "matchmaker-host-document-updated";
                notify(reply, lobby, 2006);
                return reply;
            }
            return std::nullopt;
        }
    } // namespace

    bool matchmakingDeliveryValid(const std::filesystem::path &directory,
                                  uint32_t title,
                                  const Delivery &delivery)
    {
        if (!delivery.lobbyId)
            return true;
        const auto root = directory / "matchmaking" / std::to_string(title);
        const auto path = root / "lobbies" / (std::to_string(delivery.lobbyId) + ".json");
        if (!std::filesystem::exists(path))
            return false;
        platform::LobbyIdentity id;
        id.titleId = title;
        const auto lobby = loadLobby(path, id);
        if (lobby.value("disbanded", false) || lobby.at("expires").get<uint64_t>() <= now() ||
            !member(lobby, delivery.user))
            return false;
        if (delivery.searchId)
        {
            const auto searchPath =
                root / "searches" / (std::to_string(delivery.searchId) + ".json");
            if (!std::filesystem::exists(searchPath) ||
                std::filesystem::file_size(searchPath) > 128 * 1024)
                return false;
            std::ifstream stream(searchPath);
            Json search;
            stream >> search;
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
