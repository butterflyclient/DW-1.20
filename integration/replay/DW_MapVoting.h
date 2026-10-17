#pragma once
// Original Replay identities and layouts, relocated by the source compiler.
// Native party messages already replicate human choices; no new vote transport
// or local invented voter is introduced by this frontend bridge.
extern "C"
{
    void replay_rva_01191980(unsigned, unsigned, unsigned); // Party_SetupVoteEntries
    void replay_rva_0118fdc0(void *, unsigned);             // Native local vote setter
    uint64_t *replay_rva_0118cf60(uint64_t *, const void *, int); // Party_GetXuid
    void replay_rva_010d23e0(int, unsigned);                // Playlist_RunRules
    const char *replay_rva_01b9d510(int);                   // Native vote-map display name
    bool replay_rva_0118e960(const void *);                // Party_IsPrivateParty
}

namespace dwMapVoting
{
    dvar_t *active{}, *complete{}, *cycle{}, *remaining{}, *choiceCount{}, *winner{};
    dvar_t *entries[3]{}, *votes[3]{}, *select[3]{};
    dvar_t *allocation[4]{};
    uint64_t lobby = 0;
    int observedCycle = -1, appliedWinner = -1;
    int requiredCycle = 0;
    bool wasHost = false;
    unsigned lastDirty = 0;
    char document[16384]{};

    void Register()
    {
        active = Dvar_RegisterBool("replay_dw_mapVoteActive", false, 0, "DW native map ballot active");
        complete = Dvar_RegisterBool("replay_dw_mapVoteComplete", false, 0, "DW native map ballot frozen");
        cycle = Dvar_RegisterInt("replay_dw_mapVoteCycle", 0, 0, 0x7FFFFFFF, 0, "DW map ballot round");
        remaining = Dvar_RegisterInt("replay_dw_mapVoteRemainingMs", 0, 0, 30000, 0, "DW map ballot remaining milliseconds");
        choiceCount = Dvar_RegisterInt("replay_dw_mapVoteChoiceCount", 0, 0, 3, 0, "Eligible native map choices");
        winner = Dvar_RegisterInt("replay_dw_mapVoteWinner", 0, 0, 2, 0, "Frozen native map choice");
        const char *entryNames[] = {"replay_dw_mapVoteEntryA", "replay_dw_mapVoteEntryB", "replay_dw_mapVoteEntryC"};
        const char *voteNames[] = {"replay_dw_mapVoteVotesA", "replay_dw_mapVoteVotesB", "replay_dw_mapVoteVotesC"};
        const char *selectNames[] = {"replay_dw_mapVoteSelectA", "replay_dw_mapVoteSelectB", "replay_dw_mapVoteSelectC"};
        for (unsigned i = 0; i < 3; ++i)
        {
            entries[i] = Dvar_RegisterInt(entryNames[i], 0, 0, 19, 0, "Native playlist map-vote entry");
            votes[i] = Dvar_RegisterInt(voteNames[i], 0, 0, 200, 0, "Connected primary human votes");
            select[i] = Dvar_RegisterBool(selectNames[i], false, 0, "Frontend native map-vote button");
        }
        const char *allocationNames[] = {"replay_dw_mapVoteLobby0", "replay_dw_mapVoteLobby1", "replay_dw_mapVoteLobby2", "replay_dw_mapVoteLobby3"};
        for (unsigned i = 0; i < 4; ++i)
            allocation[i] = Dvar_RegisterInt(allocationNames[i], 0, 0, 65535, 0, "Exact native ballot lobby identity");
    }

    bool Eligible(const void *party)
    {
        return DW_LocalBackend_IsEnabled() && party && Com_FrontEndScene_IsActive() &&
               replay_rva_0118dd00(party) && !replay_rva_01528420() &&
               !replay_rva_0118e960(party) &&
               !*reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 80096) &&
               Com_GameMode_GetActiveGameMode() != 3 && gl_14D386820 &&
               !gl_14D386820->current.enabled && DVARBOOL_onlinegame &&
               DVARBOOL_onlinegame->current.enabled;
    }

    bool Pending(const void *party)
    {
        // The first native create callback can become launch-ready before its
        // host snapshot receives the ballot acknowledgement. This client has
        // opted in, so that publication also gates the initial launch window.
        const auto current = *reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 79656);
        uint64_t acknowledged = 0;
        for (unsigned part = 0; active && part < 4; ++part)
            acknowledged |= uint64_t(unsigned(allocation[part]->current.integer)) << (part * 16);
        return active && Eligible(party) && current &&
               (current != acknowledged || cycle->current.integer < requiredCycle ||
                !active->current.enabled || !complete->current.enabled || appliedWinner < 0);
    }

    bool Acknowledged(uint64_t current)
    {
        uint64_t published = 0;
        for (unsigned part = 0; part < 4; ++part)
            published |= uint64_t(unsigned(allocation[part]->current.integer)) << (part * 16);
        return current && current == published && cycle->current.integer >= requiredCycle;
    }

    void ClearSelections()
    {
        for (auto *value : select)
            if (value && value->current.enabled)
            {
                DvarValue off{};
                Dvar_SetVariant(value, &off, 0);
            }
    }

    void Suspend()
    {
        // A completed publication belongs to the round that just launched.
        // Keep the allocation identity, but demand a newer backend round when
        // the frontend returns before its first intermission snapshot arrives.
        if (lobby && observedCycle >= requiredCycle && complete && complete->current.enabled)
            requiredCycle = observedCycle + 1;
        observedCycle = -1;
        appliedWinner = -1;
        wasHost = false;
        ClearSelections();
    }

    unsigned CurrentEntry(const void *party)
    {
        const auto *bytes = static_cast<const uint8_t *>(party);
        const auto position = *reinterpret_cast<const unsigned *>(bytes + 351908);
        if (position >= 8)
            return 20;
        const auto entry = bytes[351896 + position];
        return entry;
    }

    bool PrimaryConnected(uint64_t user)
    {
        // The same complete-primary filter as Replay's host snapshot writer.
        const auto head = reinterpret_cast<uintptr_t>(replay_rva_0c27e4b0 + 46424);
        auto node = *reinterpret_cast<const uintptr_t *>(replay_rva_0c27e4b0 + 46432);
        for (unsigned count = 0; node && node != head && count < 200; ++count)
        {
            const auto *bytes = reinterpret_cast<const uint8_t *>(node);
            if (bytes[121] && *reinterpret_cast<const uint64_t *>(bytes + 104) == user &&
                *reinterpret_cast<const unsigned *>(bytes + 184) == 2 &&
                *reinterpret_cast<const unsigned *>(bytes + 16) != 6)
                return true;
            node = *reinterpret_cast<const uintptr_t *>(bytes + 8);
        }
        return false;
    }

    void Frame(void *party)
    {
        if (!active || !Eligible(party))
        {
            lobby = 0;
            observedCycle = -1;
            appliedWinner = -1;
            wasHost = false;
            ClearSelections();
            return;
        }
        const auto currentLobby = *reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 79656);
        if (currentLobby != lobby)
        {
            lobby = currentLobby;
            requiredCycle = 0;
            observedCycle = -1;
            appliedWinner = -1;
            lastDirty = 0;
            ClearSelections();
            replay_rva_0118fdc0(party, 0);
            static_cast<uint8_t *>(party)[311044] = 0;
        }
        const bool host = replay_rva_01189120(party);
        if (host && !wasHost)
            appliedWinner = -1;
        wasHost = host;
        const unsigned now = replay_rva_0148fce0();
        if (host && lobby && (!lastDirty || unsigned(now - lastDirty) >= 1000) &&
            (!Acknowledged(lobby) || !active->current.enabled || !complete->current.enabled))
        {
            // Ordinary host snapshots carry the handshake and live tally.
            *reinterpret_cast<bool *>(replay_rva_0c27e4b0 + 79636) = true;
            *reinterpret_cast<unsigned *>(replay_rva_0c27e4b0 + 79640) = 0;
            lastDirty = now;
        }
        if (!Acknowledged(lobby) || !active->current.enabled || choiceCount->current.integer < 1)
        {
            observedCycle = -1;
            appliedWinner = -1;
            ClearSelections();
            return;
        }
        auto *bytes = static_cast<uint8_t *>(party);
        const unsigned count = unsigned(choiceCount->current.integer);
        if (observedCycle != cycle->current.integer)
        {
            observedCycle = cycle->current.integer;
            appliedWinner = -1;
            ClearSelections();
            const unsigned a = unsigned(entries[0]->current.integer);
            const unsigned b = count > 1 ? unsigned(entries[1]->current.integer) : a;
            const unsigned c = count > 2 ? unsigned(entries[2]->current.integer) : a;
            const auto position = *reinterpret_cast<unsigned *>(bytes + 351908);
            if (position < 8)
                bytes[351896 + position] = uint8_t(a);
            bytes[351904] = uint8_t(b);
            bytes[351905] = uint8_t(c);
            replay_rva_01191980(a, b, c);
            replay_rva_0118fdc0(party, 0); // Clear the previous round's own vote.
            bytes[311044] = 0;
        }
        for (unsigned i = 0; i < 3; ++i)
            if (select[i]->current.enabled)
            {
                DvarValue off{};
                Dvar_SetVariant(select[i], &off, 0);
                if (!complete->current.enabled && i < count)
                    replay_rva_0118fdc0(party, i + 1);
            }
        if (!complete->current.enabled)
        {
            bytes[311044] = 0;
            return;
        }
        const unsigned selected = unsigned(winner->current.integer);
        if (selected >= count || appliedWinner == int(selected))
            return;
        const auto entry = unsigned(entries[selected]->current.integer);
        if (host)
        {
            const auto position = *reinterpret_cast<unsigned *>(bytes + 351908);
            if (position >= 8)
                return;
            bytes[351896 + position] = uint8_t(entry);
            const int controller = *reinterpret_cast<const int *>(replay_rva_0c27e4b0 + 8);
            replay_rva_010d23e0(controller, entry);
            replay_rva_0119a5a0(party);
        }
        bytes[311044] = 1;
        appliedWinner = int(selected);
    }

    void HostDocument(uint64_t value, const char **source, unsigned *length)
    {
        auto *party = replay_rva_01187ee0();
        if (!active || !Eligible(party) || !replay_rva_01189120(party) || !value ||
            !source || !*source || !length || *length < 3 || *length > sizeof(document) - 96 ||
            CurrentEntry(party) >= 20 ||
            (*source)[*length - 1] != 0 || (*source)[*length - 2] != '}')
            return;
        for (unsigned i = 0; i < *length - 2; ++i)
            document[i] = (*source)[i];
        unsigned used = *length - 2;
        int added = Com_sprintf(document + used, sizeof(document) - used,
                               ",\"dw_map_vote\":{\"version\":1,\"entry\":%u,\"votes\":{", CurrentEntry(party));
        if (added <= 0 || unsigned(added) >= sizeof(document) - used)
            return;
        used += unsigned(added);
        bool first = true;
        for (unsigned slot = 0; slot < 200; ++slot)
        {
            if (!replay_rva_0118e020(party, slot))
                continue; // Native bot slots have no real member index data.
            const auto *member = static_cast<const uint8_t *>(party) + 2292 + slot * 488;
            const auto choice = *reinterpret_cast<const unsigned *>(member);
            if (!Acknowledged(value) || member[302] < 5 || choice < 1 || choice > unsigned(choiceCount->current.integer))
                continue;
            uint64_t user = 0;
            replay_rva_0118cf60(&user, party, int(slot));
            if (!user || !PrimaryConnected(user))
                continue;
            added = Com_sprintf(document + used, sizeof(document) - used,
                                "%s\"%llu\":%u", first ? "" : ",", user, choice);
            if (added <= 0 || unsigned(added) >= sizeof(document) - used - 4)
                return;
            used += unsigned(added);
            first = false;
        }
        added = Com_sprintf(document + used, sizeof(document) - used, "}}}");
        if (added != 3)
            return;
        *source = document;
        *length = used + 4;
    }

    int UIState(char *output, unsigned capacity)
    {
        auto *party = replay_rva_01187ee0();
        if (!active || !active->current.enabled ||
            !Acknowledged(*reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 79656)) ||
            !Eligible(party))
            return Com_sprintf(output, capacity, "{active=false}");
        // Native Party_Vote updates this same local choice before the host
        // tallies it. Expose acknowledgement, not an invented Lua-side vote.
        const auto choice = *reinterpret_cast<const unsigned *>(static_cast<const uint8_t *>(party) + 311148);
        unsigned used = unsigned(Com_sprintf(output, capacity,
            "{active=true,complete=%s,remaining=%d,round=%d,selected=%d,choices={",
            complete->current.enabled ? "true" : "false", (remaining->current.integer + 999) / 1000,
            cycle->current.integer, choice <= unsigned(choiceCount->current.integer) ? int(choice) : 0));
        for (unsigned i = 0; i < unsigned(choiceCount->current.integer); ++i)
        {
            const char *map = replay_rva_01b9d510(int(i));
            char escaped[256]{};
            unsigned count = 0;
            for (unsigned character = 0; map && map[character] && character < 120; ++character)
            {
                const char value = map[character];
                if (value == '\'' || value == '\\')
                    escaped[count++] = '\\';
                escaped[count++] = static_cast<unsigned char>(value) < 32 ? ' ' : value;
            }
            const int added = Com_sprintf(output + used, capacity - used,
                "%s{name='%s',votes=%d,winner=%s}", i ? "," : "", escaped, votes[i]->current.integer,
                complete->current.enabled && winner->current.integer == int(i) ? "true" : "false");
            if (added <= 0 || unsigned(added) >= capacity - used - 3)
                return 0;
            used += unsigned(added);
        }
        const int tail = Com_sprintf(output + used, capacity - used, "}}");
        return tail == 2 ? int(used + 2) : 0;
    }
}
