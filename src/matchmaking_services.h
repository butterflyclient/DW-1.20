#pragma once
#include "services.h"
#include "lobby.h"
#include "matchmaking_store.h"
#include "operator_controls.h"
#include <optional>
#include <set>

namespace services
{
    OperatorMatchStart matchmakingStartWaitingMatch(
        const std::filesystem::path &directory,
        const std::vector<lobby::OnlinePlayer> &players,
        const std::string &matchToken,
        bool fillBots = false,
        unsigned botCount = 0);
    nlohmann::json matchmakingPublicActivity(const std::filesystem::path &directory,
                                             const std::vector<lobby::OnlinePlayer> &players);

    struct TournamentLobbyPlan
    {
        uint64_t lobbyId = 0;
        std::vector<matchmaking_store::Write> writes;
    };

    // Prepare complete native lobby snapshots. The tournament owner commits these
    // with the bracket/enrollment in one recoverable transaction.
    std::optional<TournamentLobbyPlan> prepareTournamentRoundLobby(
        const std::filesystem::path &directory,
        uint32_t title,
        uint64_t tournament,
        unsigned round,
        unsigned match,
        const nlohmann::json &teams,
        const std::vector<nlohmann::json> &searches,
        const nlohmann::json &query,
        uint64_t expires,
        const std::string &requiredMap = {});
    std::optional<Delivery> tournamentRoundLobbyDelivery(const std::filesystem::path &directory,
                                                         uint32_t title,
                                                         uint64_t user,
                                                         uint64_t tournament,
                                                         uint64_t lobby,
                                                         const nlohmann::json &metadata);
    uint32_t matchmakingHostAuthorized(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &identity,
                                       uint64_t lobby,
                                       std::span<const uint64_t> participants);
    std::optional<platform::LobbyIdentity> matchmakingReportIdentity(
        const std::filesystem::path &directory,
        const platform::LobbyIdentity &sender,
        uint64_t participant);
    std::optional<unsigned> matchmakingPublicMatchCategory(
        const std::filesystem::path &directory,
        const platform::LobbyIdentity &identity);
    struct PublicMatchContext
    {
        uint64_t lobby = 0;
        unsigned category = 0;
        std::string session;
        std::set<std::string> gameTypes;
    };
    // Capture while the exact issuing session belongs to a public allocation.
    // Starting events may arrive before the native host reports in_game.
    std::optional<PublicMatchContext> matchmakingPublicMatchContext(
        const std::filesystem::path &directory,
        const platform::LobbyIdentity &identity,
        bool requireInGame = true);
    bool matchmakingDeliveryValid(const std::filesystem::path &directory,
                                  uint32_t title,
                                  const Delivery &delivery);
    std::optional<Reply> matchmakingServices(const std::filesystem::path &directory,
                                             const platform::LobbyIdentity &identity,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &parameters);
} // namespace services
