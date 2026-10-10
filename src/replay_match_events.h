#pragma once
#include "crypto.h"
#include "matchmaking_services.h"
#include "quest_services.h"
#include "replay_challenge_game_type.h"
#include <algorithm>
#include <charconv>

namespace services
{
    struct ReplayMatchProgress
    {
        nlohmann::json matches;
        std::vector<ReplayQuestEventContext> contexts;
    };

    inline uint64_t replayMatchNumber(const nlohmann::json &value, const char *key)
    {
        wire::require(value.contains(key) && value.at(key).is_number_unsigned());
        return value.at(key).get<uint64_t>();
    }

    inline void validateReplayMatches(const nlohmann::json &matches)
    {
        wire::require(matches.is_object() && matches.size() <= 4096);
        for (const auto &entry : matches.items())
        {
            uint64_t native = 0;
            const auto &key = entry.key();
            const auto parsed = std::from_chars(key.data(), key.data() + key.size(), native);
            wire::require(parsed.ec == std::errc{} && parsed.ptr == key.data() + key.size() &&
                          native && native != UINT64_MAX && std::to_string(native) == key);
            const auto &row = entry.value();
            wire::require(row.is_object() && row.size() == 9 && row.at("schema") == 1 &&
                          replayMatchNumber(row, "lobby") &&
                          replayMatchNumber(row, "category") <= 1 &&
                          replayMatchNumber(row, "mode") <= UINT32_MAX &&
                          !replayChallengeGameTypeName(static_cast<uint32_t>(replayMatchNumber(row, "mode"))).empty() &&
                          row.at("sessions").is_array() && !row["sessions"].empty() &&
                          row["sessions"].size() <= 64 &&
                          replayMatchNumber(row, "start") > 0 &&
                          replayMatchNumber(row, "expires") >= replayMatchNumber(row, "start") &&
                          replayMatchNumber(row, "outcome") <= 3);
            const auto end = replayMatchNumber(row, "end");
            wire::require(replayMatchNumber(row, "category") ==
                (replayChallengeGameTypeName(static_cast<uint32_t>(replayMatchNumber(row, "mode"))) == "br" ? 1u : 0u));
            wire::require((end == 0 && row.at("outcome") == 0) ||
                          (end >= replayMatchNumber(row, "start") &&
                           end <= replayMatchNumber(row, "expires")));
            std::set<std::string> sessions;
            for (const auto &session : row.at("sessions"))
                wire::require(session.is_string() && session.get_ref<const std::string &>().size() == 44 &&
                              sessions.insert(session.get<std::string>()).second);
        }
    }

    // The native start packet contains [match ID, specific game type]. Other
    // packets use the additional dw_match_id key, within the SDK's ten-pair
    // capacity. Bind only against a server-validated allocation/session, never
    // against a public-looking event name or the client's gamemode alone.
    inline ReplayMatchProgress prepareReplayMatchEvents(
        const nlohmann::json &stored,
        const nlohmann::json &events,
        const platform::LobbyIdentity &identity,
        const std::optional<PublicMatchContext> &allocation,
        std::optional<unsigned> legacyCategory,
        uint64_t serverTime)
    {
        using Json = nlohmann::json;
        validateReplayMatches(stored);
        wire::require(events.is_array() && events.size() <= 128 && serverTime < UINT64_MAX - 604800);
        ReplayMatchProgress result{stored, {}};
        const auto session = wire::base64Encode(crypto::sha256(identity.key));
        wire::require(session.size() == 44);
        // Expiry uses server time, not the incoming timestamp. No live match is
        // evicted to make room; capacity failure rejects the whole transaction.
        for (auto row = result.matches.begin(); row != result.matches.end();)
            if (replayMatchNumber(row.value(), "expires") < serverTime)
                row = result.matches.erase(row);
            else
                ++row;
        for (const auto &event : events)
        {
            const auto &values = event.at("values");
            const auto &name = event.at("name");
            const auto timestamp = replayMatchNumber(event, "timestamp");
            const bool tagged = values.contains("dw_match_id");
            const auto native = tagged ? replayMatchNumber(values, "dw_match_id") : uint64_t{0};
            const auto family = values.value("gamemode", uint64_t{0});
            const bool versioned = values.value("version", uint64_t{0}) == 1;
            if (name == "start_match" && versioned && allocation && timestamp &&
                timestamp <= serverTime + 300 && values.contains("Param0") && values.contains("Param1") &&
                values.contains("dw_lobby_id") && replayMatchNumber(values, "dw_lobby_id") == allocation->lobby)
            {
                const auto startId = replayMatchNumber(values, "Param0");
                const auto mode = replayMatchNumber(values, "Param1");
                const bool familyMatches = allocation->category == 0 ? family == 2 : family == 8 || family == 24;
                if (startId && startId != UINT64_MAX && (!tagged || native == startId) &&
                    allocation->session == session && familyMatches && mode <= UINT32_MAX &&
                    allocation->gameTypes.contains(std::string(replayChallengeGameTypeName(static_cast<uint32_t>(mode)))))
                {
                    const auto key = std::to_string(startId);
                    if (!result.matches.contains(key))
                    {
                        wire::require(result.matches.size() < 4096);
                        result.matches[key] = Json{{"schema", 1}, {"lobby", allocation->lobby},
                            {"category", allocation->category}, {"mode", mode},
                            {"sessions", Json::array({session})}, {"start", timestamp},
                            {"expires", serverTime + 604800}, {"end", uint64_t{0}}, {"outcome", uint64_t{0}}};
                    }
                    else
                    {
                        auto &row = result.matches.at(key);
                        // A new login can join a still-running allocation, but
                        // cannot replace its original match or reopen its result.
                        wire::require(row.at("lobby") == allocation->lobby && row.at("mode") == mode &&
                                      row.at("category") == allocation->category);
                        auto &sessions = row.at("sessions");
                        if (row.at("end") == 0 && std::find(sessions.begin(), sessions.end(), session) == sessions.end())
                        {
                            wire::require(sessions.size() < 64);
                            sessions.push_back(session);
                        }
                    }
                }
            }
            std::optional<unsigned> category = tagged ? std::nullopt : legacyCategory;
            auto cutoff = timestamp;
            const auto found = result.matches.find(std::to_string(native));
            if (tagged && found != result.matches.end() && timestamp <= serverTime + 300)
            {
                auto &row = found.value();
                const auto &sessions = row.at("sessions");
                if (timestamp >= replayMatchNumber(row, "start") &&
                    timestamp <= replayMatchNumber(row, "expires") &&
                    std::find(sessions.begin(), sessions.end(), session) != sessions.end())
                {
                    const auto ended = replayMatchNumber(row, "end");
                    const bool cached = name == "pickup" || name == "driving" || name == "alive_in_gas" ||
                                        name == "alive_not_downed" || name == "mp_addxp";
                    if (!ended || timestamp <= ended || cached || name == "end_match")
                        category = static_cast<unsigned>(replayMatchNumber(row, "category"));
                    if (ended)
                        cutoff = std::min(cutoff, ended);
                    const auto capturedCategory = static_cast<unsigned>(replayMatchNumber(row, "category"));
                    const bool familyMatches = capturedCategory == 0 ? family == 2 : family == 8 || family == 24;
                    if (name == "end_match" && versioned && values.contains("Param0") && values.contains("Param1") &&
                        values.contains("Param2") && values.contains("Param3") && values.contains("Param4") &&
                        (replayMatchNumber(values, "Param0") & UINT32_MAX) == replayMatchNumber(row, "mode") &&
                        replayMatchNumber(values, "Param1") <= 3 && familyMatches && row.at("end") == 0)
                    {
                        row["end"] = timestamp;
                        row["outcome"] = replayMatchNumber(values, "Param1");
                    }
                }
            }
            result.contexts.push_back({category, cutoff});
        }
        validateReplayMatches(result.matches);
        return result;
    }
} // namespace services
