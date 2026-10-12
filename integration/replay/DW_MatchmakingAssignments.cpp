#include "DW_MatchmakingAssignmentBindings.h"
#include "replay_dvar.h"
#include <stddef.h>
#include <stdint.h>
#include <intrin.h>

namespace DWMatchmaking
{
    struct Link
    {
        Link *previous;
        Link *next;
    };

    struct AssignmentNode
    {
        AssignmentNode *previous;
        AssignmentNode *next;
        uint64_t xuid;
        int32_t assignment;
        uint32_t reserved;
    };

    // Complete Replay fixed_list<PlayerValue<int>,200> storage. The native
    // parser owns allocation, insertion, removal and the lifetime of this list.
    struct AssignmentList
    {
        AssignmentNode pool[200];
        AssignmentNode *free;
        Link head;
    };

    // This view spans the fields used by the original two update routines.
    // The complete player allocation remains owned by the native matchmaker.
    struct PlayerView
    {
        PlayerView *previous;
        PlayerView *next;
        uint8_t opaque16[88];
        uint64_t xuid;
        uint8_t opaque112[80];
        int32_t team;
        int32_t squad;
    };

    struct MatchmakerView
    {
        uint8_t opaque0[46424];
        Link players;
    };

    static_assert(sizeof(Link) == 16);
    static_assert(sizeof(AssignmentNode) == 32);
    static_assert(offsetof(AssignmentNode, xuid) == 16);
    static_assert(offsetof(AssignmentNode, assignment) == 24);
    static_assert(sizeof(AssignmentList) == 6424);
    static_assert(offsetof(AssignmentList, free) == 6400);
    static_assert(offsetof(AssignmentList, head) == 6408);
    static_assert(offsetof(PlayerView, xuid) == 104);
    static_assert(offsetof(PlayerView, team) == 192);
    static_assert(offsetof(PlayerView, squad) == 196);
    static_assert(offsetof(MatchmakerView, players) == 46424);
} // namespace DWMatchmaking

extern "C"
{
    bool DW_BotPolicy_IsBattleRoyale();
    void *DWMA_LobbyParty();
    bool DWMA_XuidEqual(const uint64_t *, const uint64_t *);
    const char *DWMA_XuidString(const uint64_t *);
    void DWMA_Print(int, const char *, ...);
    void DWMA_Warning(int, const char *, ...);
    void DWMA_SetTeam(void *, uint64_t, int32_t);
    void DWMA_SetSquad(void *, uint64_t, int32_t);
    extern dvar_t *DWMA_UpdateAssignments;
    uint64_t DWMA_LobbyIdentity(const void *);
    extern uint8_t DWMA_CurrentMatchmaker[];
}

namespace
{
    struct CachedAssignment
    {
        uint64_t xuid;
        int32_t assignment;
        uint32_t reserved;
    };

    static_assert(sizeof(CachedAssignment) == 16);
    CachedAssignment s_teams[200]{}, s_squads[200]{};
    unsigned s_teamCount{}, s_squadCount{};
    const void *s_receiver = nullptr;
    uint64_t s_lobby = 0;
    uint64_t s_revision = 0;
    volatile long s_cacheLock = 0;

    struct CacheGuard
    {
        CacheGuard()
        {
            while (_InterlockedCompareExchange(&s_cacheLock, 1, 0))
                _mm_pause();
        }

        ~CacheGuard()
        {
            _InterlockedExchange(&s_cacheLock, 0);
        }

        CacheGuard(const CacheGuard &) = delete;
        CacheGuard &operator=(const CacheGuard &) = delete;
    };

    struct CacheSnapshot
    {
        CachedAssignment teams[200], squads[200];
        unsigned teamCount, squadCount;
        const void *receiver;
        uint64_t lobby, revision;
    };

    void clearLocked()
    {
        s_teamCount = s_squadCount = 0;
        s_receiver = nullptr;
        s_lobby = 0;
        ++s_revision;
    }

    void clearCache()
    {
        CacheGuard guard;
        clearLocked();
    }

    void clearRevision(uint64_t revision)
    {
        CacheGuard guard;
        if (s_revision == revision)
            clearLocked();
    }

    bool takeSnapshot(CacheSnapshot &snapshot)
    {
        CacheGuard guard;
        if (!s_lobby || s_receiver != DWMA_CurrentMatchmaker)
        {
            clearLocked();
            return false;
        }
        snapshot.teamCount = s_teamCount;
        snapshot.squadCount = s_squadCount;
        snapshot.receiver = s_receiver;
        snapshot.lobby = s_lobby;
        snapshot.revision = s_revision;
        for (unsigned index = 0; index < s_teamCount; ++index)
            snapshot.teams[index] = s_teams[index];
        for (unsigned index = 0; index < s_squadCount; ++index)
            snapshot.squads[index] = s_squads[index];
        return true;
    }

    bool snapshotCurrent(const CacheSnapshot &snapshot)
    {
        if (!DWMA_UpdateAssignments->current.enabled || !DW_BotPolicy_IsBattleRoyale() ||
            DWMA_LobbyIdentity(DWMA_CurrentMatchmaker) != snapshot.lobby)
            return false;
        CacheGuard guard;
        return s_revision == snapshot.revision && s_receiver == snapshot.receiver &&
               s_lobby == snapshot.lobby;
    }

    void remember(DWMatchmaking::MatchmakerView *matchmaker,
                  const DWMatchmaking::AssignmentList *assignments,
                  bool squad,
                  bool authoritative)
    {
        if (!authoritative || reinterpret_cast<const void *>(matchmaker) != DWMA_CurrentMatchmaker)
        {
            clearCache();
            return;
        }
        const uint64_t lobby = DWMA_LobbyIdentity(matchmaker);
        if (!lobby)
        {
            clearCache();
            return;
        }
        CacheGuard guard;
        if (s_receiver != matchmaker || s_lobby != lobby)
        {
            clearLocked();
            s_receiver = matchmaker;
            s_lobby = lobby;
        }
        unsigned &count = squad ? s_squadCount : s_teamCount;
        auto *cache = squad ? s_squads : s_teams;
        count = 0;
        const auto *sentinel =
            reinterpret_cast<const DWMatchmaking::AssignmentNode *>(&assignments->head);
        auto *entry =
            reinterpret_cast<const DWMatchmaking::AssignmentNode *>(assignments->head.next);
        while (entry != sentinel && count < 200)
        {
            cache[count++] = {entry->xuid, entry->assignment, 0};
            entry = entry->next;
        }
        ++s_revision;
    }

    DWMatchmaking::PlayerView *find(DWMatchmaking::MatchmakerView *matchmaker, const uint64_t &xuid)
    {
        const auto *sentinel =
            reinterpret_cast<const DWMatchmaking::PlayerView *>(&matchmaker->players);
        auto *player = reinterpret_cast<DWMatchmaking::PlayerView *>(matchmaker->players.next);
        while (player != sentinel)
        {
            if (DWMA_XuidEqual(&xuid, &player->xuid))
                return player;
            player = player->next;
        }
        return nullptr;
    }

    void update(DWMatchmaking::MatchmakerView *matchmaker,
                const DWMatchmaking::AssignmentList *assignments,
                bool squad)
    {
        const char *method = squad ? "OnlineMatchmakerOmniscient::UpdateSquadAssignments"
                                   : "OnlineMatchmakerOmniscient::UpdateTeamAssignments";
        DWMA_Print(25, "[MM] %s STARTING\n", method);
        void *party = DWMA_LobbyParty();
        const bool enabled = DWMA_UpdateAssignments->current.enabled;
        const bool authoritative = enabled && DW_BotPolicy_IsBattleRoyale();
        remember(matchmaker, assignments, squad, authoritative);
        const auto *sentinel =
            reinterpret_cast<const DWMatchmaking::AssignmentNode *>(&assignments->head);
        auto *assignment =
            reinterpret_cast<const DWMatchmaking::AssignmentNode *>(assignments->head.next);
        while (assignment != sentinel)
        {
            bool changed = false;
            if (auto *player = find(matchmaker, assignment->xuid))
            {
                int32_t &cached = squad ? player->squad : player->team;
                if (cached != assignment->assignment)
                {
                    DWMA_Print(25,
                               squad ? "\tChanging user %s from squad %i to squad %i\n"
                                     : "\tChanging user %s from DW team %i to DW team %i\n",
                               DWMA_XuidString(&assignment->xuid),
                               cached,
                               assignment->assignment);
                    cached = assignment->assignment;
                    changed = true;
                }
            }
            else
            {
                DWMA_Warning(25,
                             "\t%s user %s not found, this is bad\n",
                             method,
                             DWMA_XuidString(&assignment->xuid));
            }
            // A remote member may enter the host lobby after the local player
            // cache was populated. Reapply the authoritative DW BR assignment
            // on every native document update; the stock setters retain their
            // member-presence, active-party, game-mode and notification guards.
            if (enabled && (changed || authoritative))
            {
                if (squad)
                    DWMA_SetSquad(party, assignment->xuid, assignment->assignment);
                else
                    DWMA_SetTeam(party, assignment->xuid, assignment->assignment + 1);
            }
            assignment = assignment->next;
        }
        DWMA_Print(25, "[MM] %s COMPLETE\n", method);
    }

    extern "C" void DW_MatchmakingAssignments_PrepareLaunch(const void *party)
    {
        void *currentParty = DWMA_LobbyParty();
        if (!DWMA_UpdateAssignments->current.enabled || !DW_BotPolicy_IsBattleRoyale())
        {
            clearCache();
            return;
        }
        if (!party || party != currentParty)
            return;
        CacheSnapshot snapshot;
        if (!takeSnapshot(snapshot))
            return;
        if (!snapshotCurrent(snapshot))
        {
            clearRevision(snapshot.revision);
            return;
        }
        // Neither this cache lock nor borrowed parser storage crosses a native
        // callback. A newer document invalidates the remaining old snapshot.
        for (unsigned i = 0; i < snapshot.teamCount; ++i)
        {
            if (!snapshotCurrent(snapshot))
            {
                clearRevision(snapshot.revision);
                return;
            }
            DWMA_SetTeam(currentParty, snapshot.teams[i].xuid, snapshot.teams[i].assignment + 1);
        }
        for (unsigned i = 0; i < snapshot.squadCount; ++i)
        {
            if (!snapshotCurrent(snapshot))
            {
                clearRevision(snapshot.revision);
                return;
            }
            DWMA_SetSquad(currentParty, snapshot.squads[i].xuid, snapshot.squads[i].assignment);
        }
    }
} // namespace

extern "C" void DW_Matchmaker_UpdateTeamAssignments(
    DWMatchmaking::MatchmakerView *matchmaker, const DWMatchmaking::AssignmentList *assignments)
{
    update(matchmaker, assignments, false);
}

extern "C" void DW_Matchmaker_UpdateSquadAssignments(
    DWMatchmaking::MatchmakerView *matchmaker, const DWMatchmaking::AssignmentList *assignments)
{
    update(matchmaker, assignments, true);
}
