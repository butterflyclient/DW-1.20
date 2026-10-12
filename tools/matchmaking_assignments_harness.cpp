#include "../integration/replay/DW_MatchmakingAssignments.cpp"

extern "C"
{
    alignas(8) uint8_t DWMA_CurrentMatchmaker[sizeof(DWMatchmaking::MatchmakerView)]{};
}

namespace
{
    auto &matchmaker = *reinterpret_cast<DWMatchmaking::MatchmakerView *>(DWMA_CurrentMatchmaker);
    DWMatchmaking::AssignmentList assignments{};
    DWMatchmaking::PlayerView player{};
    DWMatchmaking::MatchmakerView foreignMatchmaker{};
    dvar_t dvar{};
    bool br, present;
    unsigned setters, applied, prints, warnings;
    int partyTeam, partySquad;
    int party;
    uint64_t lobbyIdentity = 101;
    DWMatchmaking::AssignmentList stressAssignments{};
    bool reenterCallback = false;
    unsigned callbackLockFailures = 0;
} // namespace

extern "C"
{
    dvar_t *DWMA_UpdateAssignments = &dvar;

    uint64_t DWMA_LobbyIdentity(const void *receiver)
    {
        return receiver == DWMA_CurrentMatchmaker ? lobbyIdentity : 0;
    }

    bool DW_BotPolicy_IsBattleRoyale()
    {
        return br;
    }

    void *DWMA_LobbyParty()
    {
        return &party;
    }

    bool DWMA_XuidEqual(const uint64_t *a, const uint64_t *b)
    {
        return *a == *b;
    }

    const char *DWMA_XuidString(const uint64_t *)
    {
        return "test-user";
    }

    void DWMA_Print(int channel, const char *, ...)
    {
        if (channel == 25)
            ++prints;
    }

    void DWMA_Warning(int channel, const char *, ...)
    {
        if (channel == 25)
            ++warnings;
    }

    void DWMA_SetTeam(void *target, uint64_t xuid, int32_t value)
    {
        if (s_cacheLock)
            ++callbackLockFailures;
        if (reenterCallback)
        {
            reenterCallback = false;
            remember(&matchmaker, &assignments, false, true);
        }
        ++setters;
        if (target == &party && xuid == 1001 && present)
        {
            ++applied;
            partyTeam = value;
        }
    }

    void DWMA_SetSquad(void *target, uint64_t xuid, int32_t value)
    {
        if (s_cacheLock)
            ++callbackLockFailures;
        ++setters;
        if (target == &party && xuid == 1001 && present)
        {
            ++applied;
            partySquad = value;
        }
    }

    __declspec(dllexport) void Test_Case(unsigned squad,
                                         unsigned enabled,
                                         unsigned dw,
                                         unsigned found,
                                         int cached,
                                         int desired,
                                         unsigned member)
    {
        clearCache();
        lobbyIdentity = 101;
        br = dw != 0;
        present = member != 0;
        dvar.current.enabled = enabled != 0;
        setters = applied = prints = warnings = 0;
        partyTeam = partySquad = -10;
        player.xuid = 1001;
        player.team = player.squad = cached;
        auto *playerSentinel = reinterpret_cast<DWMatchmaking::PlayerView *>(&matchmaker.players);
        player.previous = player.next = playerSentinel;
        matchmaker.players.previous = matchmaker.players.next =
            found ? reinterpret_cast<DWMatchmaking::Link *>(&player) : &matchmaker.players;
        auto &entry = assignments.pool[0];
        auto *assignmentSentinel =
            reinterpret_cast<DWMatchmaking::AssignmentNode *>(&assignments.head);
        entry.previous = entry.next = assignmentSentinel;
        entry.xuid = 1001;
        entry.assignment = desired;
        assignments.head.previous = assignments.head.next =
            reinterpret_cast<DWMatchmaking::Link *>(&entry);
        if (squad)
            DW_Matchmaker_UpdateSquadAssignments(&matchmaker, &assignments);
        else
            DW_Matchmaker_UpdateTeamAssignments(&matchmaker, &assignments);
    }

    __declspec(dllexport) uint64_t Test_Result(unsigned index)
    {
        const uint32_t results[] = {uint32_t(player.team),
                                    uint32_t(player.squad),
                                    setters,
                                    applied,
                                    uint32_t(partyTeam),
                                    uint32_t(partySquad),
                                    prints,
                                    warnings};
        return index < sizeof(results) / sizeof(*results) ? results[index] : 0;
    }

    __declspec(dllexport) int Test_Retry()
    {
        for (unsigned squad = 0; squad < 2; ++squad)
        {
            Test_Case(squad, 1, 1, 1, 1, 1, 0);
            if (setters != 1 || applied != 0)
                return __LINE__;
            present = true;
            if (squad)
                DW_Matchmaker_UpdateSquadAssignments(&matchmaker, &assignments);
            else
                DW_Matchmaker_UpdateTeamAssignments(&matchmaker, &assignments);
            if (setters != 2 || applied != 1 || (squad ? partySquad != 1 : partyTeam != 2))
                return __LINE__;
        }
        return 0;
    }

    __declspec(dllexport) int Test_LaunchCache()
    {
        for (unsigned found = 0; found < 2; ++found)
        {
            Test_Case(0, 1, 1, found, 1, 1, 0);
            DW_Matchmaker_UpdateSquadAssignments(&matchmaker, &assignments);
            if (setters != 2 || applied != 0)
                return __LINE__;
            present = true;
            DW_MatchmakingAssignments_PrepareLaunch(&party);
            if (setters != 4 || applied != 2 || partyTeam != 2 || partySquad != 1)
                return __LINE__;
            int foreignParty = 0;
            DW_MatchmakingAssignments_PrepareLaunch(&foreignParty);
            if (setters != 4)
                return __LINE__;
            ++lobbyIdentity;
            DW_MatchmakingAssignments_PrepareLaunch(&party);
            if (setters != 4 || s_teamCount || s_squadCount)
                return __LINE__;
        }
        for (unsigned reason = 0; reason < 4; ++reason)
        {
            Test_Case(0, 1, 1, 1, 1, 1, 0);
            if (reason == 0)
                dvar.current.enabled = false;
            if (reason == 1)
                br = false;
            if (reason == 2)
                lobbyIdentity = 0;
            if (reason == 3)
                s_receiver = &player;
            present = true;
            DW_MatchmakingAssignments_PrepareLaunch(&party);
            if (setters != 1 || applied || s_teamCount || s_squadCount)
                return __LINE__;
        }
        Test_Case(0, 1, 1, 0, 0, 1, 0);
        foreignMatchmaker.players.previous = foreignMatchmaker.players.next =
            &foreignMatchmaker.players;
        DW_Matchmaker_UpdateSquadAssignments(&foreignMatchmaker, &assignments);
        if (s_receiver || s_teamCount || s_squadCount)
            return __LINE__;
        Test_Case(0, 1, 1, 0, 0, 1, 0);
        auto *sentinel = reinterpret_cast<DWMatchmaking::AssignmentNode *>(&assignments.head);
        for (unsigned i = 0; i < 200; ++i)
        {
            auto &entry = assignments.pool[i];
            entry.previous = i ? &assignments.pool[i - 1] : sentinel;
            entry.next = i + 1 < 200 ? &assignments.pool[i + 1] : sentinel;
            entry.xuid = 1001 + i;
            entry.assignment = int(i % 40);
        }
        assignments.head.previous = reinterpret_cast<DWMatchmaking::Link *>(&assignments.pool[199]);
        DW_Matchmaker_UpdateTeamAssignments(&matchmaker, &assignments);
        if (s_teamCount != 200 || s_teams[199].xuid != 1200 || s_teams[199].assignment != 39)
            return __LINE__;
        assignments.head.previous = assignments.head.next = &assignments.head;
        DW_Matchmaker_UpdateTeamAssignments(&matchmaker, &assignments);
        if (s_teamCount)
            return __LINE__;
        return 0;
    }

    __declspec(dllexport) int Test_CallbackRevision()
    {
        Test_Case(0, 1, 1, 1, 1, 1, 1);
        DW_Matchmaker_UpdateSquadAssignments(&matchmaker, &assignments);
        const unsigned previous = setters;
        reenterCallback = true;
        DW_MatchmakingAssignments_PrepareLaunch(&party);
        if (setters != previous + 1 || callbackLockFailures || reenterCallback ||
            s_teamCount != 1 || s_squadCount != 1)
            return __LINE__;
        return 0;
    }

    __declspec(dllexport) void Test_StressInit()
    {
        clearCache();
        lobbyIdentity = 101;
        br = true;
        dvar.current.enabled = true;
        auto *sentinel = reinterpret_cast<DWMatchmaking::AssignmentNode *>(&stressAssignments.head);
        for (unsigned index = 0; index < 200; ++index)
        {
            stressAssignments.pool[index].previous =
                index ? &stressAssignments.pool[index - 1] : sentinel;
            stressAssignments.pool[index].next =
                index + 1 < 200 ? &stressAssignments.pool[index + 1] : sentinel;
        }
        stressAssignments.head.previous =
            reinterpret_cast<DWMatchmaking::Link *>(&stressAssignments.pool[199]);
        stressAssignments.head.next =
            reinterpret_cast<DWMatchmaking::Link *>(&stressAssignments.pool[0]);
    }

    __declspec(dllexport) int Test_StressWriter(unsigned iterations)
    {
        for (unsigned generation = 1; generation <= iterations; ++generation)
        {
            for (unsigned index = 0; index < 200; ++index)
            {
                stressAssignments.pool[index].xuid = (uint64_t(generation) << 32) | index;
                stressAssignments.pool[index].assignment = int32_t(generation);
            }
            remember(&matchmaker, &stressAssignments, false, true);
            remember(&matchmaker, &stressAssignments, true, true);
        }
        return 0;
    }

    __declspec(dllexport) int Test_StressReader(unsigned iterations)
    {
        CacheSnapshot snapshot;
        for (unsigned iteration = 0; iteration < iterations; ++iteration)
        {
            if (!takeSnapshot(snapshot))
                continue;
            if (snapshot.teamCount != 200 ||
                (snapshot.squadCount != 0 && snapshot.squadCount != 200))
                return __LINE__;
            for (unsigned kind = 0; kind < 2; ++kind)
            {
                const auto *values = kind ? snapshot.squads : snapshot.teams;
                const unsigned count = kind ? snapshot.squadCount : snapshot.teamCount;
                const uint64_t generation = count ? values[0].xuid >> 32 : 0;
                for (unsigned index = 0; index < count; ++index)
                    if (values[index].xuid != ((generation << 32) | index) ||
                        values[index].assignment != int32_t(generation))
                        return __LINE__;
            }
        }
        return 0;
    }
}
