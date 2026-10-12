#include "../integration/replay/DW_JoinInProgress.cpp"

namespace
{
    DWJoin::PartyView party{};
    DWJoin::ClientView clients[200]{};
    dvar_t privateMatch{}, playlist{}, anonymousDuration{}, zombieDuration{}, connectingDuration{};
    unsigned flags, capacity, maximum, calls, removals;
    int oldest[5]{}, output, result;
    DWJoin::Challenge challenge{0x64636261u, 0x0065u};
    const void *serverParty = nullptr;

    bool bit(unsigned value)
    {
        return (flags & value) != 0;
    }
} // namespace

extern "C"
{
    dvar_t *DWJIP_PrivateMatch = &privateMatch, *DWJIP_Playlist = &playlist;
    dvar_t *DWJIP_AnonymousDuration = &anonymousDuration, *DWJIP_ZombieDuration = &zombieDuration;
    dvar_t *DWJIP_ConnectingDuration = &connectingDuration;
    unsigned DWJIP_ClientCount = 200;
    DWJoin::ClientView *DWJIP_Clients[200]{};

    bool DW_LocalBackend_IsEnabled()
    {
        return bit(1);
    }

    int DWJIP_GameSlots(const void *)
    {
        return int(capacity);
    }

    bool DWJIP_GameLobby(const void *)
    {
        return bit(2);
    }

    unsigned DWJIP_PlaylistId(int)
    {
        return 7;
    }

    int DWJIP_MaxHumanPlayers(unsigned)
    {
        return int(maximum);
    }

    int DWJIP_OldestSlot(const void *, int status, int)
    {
        return oldest[status];
    }

    bool DWJIP_LocalServerRunning()
    {
        return bit(4);
    }

    bool DWJIP_ServerLoaded()
    {
        return bit(8);
    }

    bool DWJIP_AreWeHost(const void *)
    {
        return bit(16);
    }

    const void *DWJIP_ServerLobby()
    {
        return bit(32) ? serverParty : nullptr;
    }

    bool DWJIP_IsBot(unsigned index)
    {
        return bit(64) && index == 4;
    }

    void DWJIP_Print(int, const char *, ...)
    {
        ++calls;
    }

    const char *DWJIP_XuidString(const uint64_t *)
    {
        return "user";
    }

    void DWJIP_RemoveMember(void *, int, int, const char *, int)
    {
        ++removals;
    }

    void *DWJIP_XuidAssign(uint64_t *out, const uint64_t *in)
    {
        *out = *in;
        return out;
    }

    unsigned DWJIP_Milliseconds()
    {
        return 777;
    }

    void *DWJIP_Zero(void *address, int, size_t length)
    {
        auto *bytes = static_cast<volatile uint8_t *>(address);
        for (size_t index = 0; index < length; ++index)
            bytes[index] = 0;
        return address;
    }

    __declspec(dllexport) void Test_Case(
        unsigned scenario, unsigned mask, unsigned slots, unsigned maxHumans, unsigned privateMode)
    {
        flags = mask;
        DWJIP_ClientCount = 200;
        capacity = slots;
        maximum = maxHumans;
        privateMatch.current.enabled = privateMode != 0;
        playlist.current.integer = 1;
        anonymousDuration.current.integer = 11;
        zombieDuration.current.integer = 12;
        connectingDuration.current.integer = 13;
        calls = removals = 0;
        output = -99;
        for (unsigned index = 0; index < 200; ++index)
        {
            DWJIP_Zero(&party.members[index], 0, sizeof(DWJoin::Member));
            party.members[index].status = 5;
            clients[index].state = bit(128) ? 5 : 2;
            DWJIP_Clients[index] = &clients[index];
        }
        for (auto &word : party.dirtyMembers)
            word = 0xffffffffu;
        party.name = "test";
        serverParty = &party;
        for (auto &value : oldest)
            value = -1;
        if (scenario == 0 || scenario == 5 || scenario == 6)
        {
            party.members[0].status = 0;
            if (scenario != 5)
                party.members[4].status = 0;
            if (scenario == 6)
                party.members[0].status = 2;
        }
        else if (scenario >= 1 && scenario <= 3)
        {
            oldest[scenario + 1] = 7;
            party.members[7].status = uint8_t(scenario + 1);
        }
        result = DW_PartyAtomicHost_AddAnonymousMember(
            &party, 0x1122334455667788ull, &challenge, &output);
    }

    __declspec(dllexport) uint64_t Test_Result(unsigned index)
    {
        if (index == 0)
            return unsigned(result);
        if (index == 1)
            return unsigned(output);
        if (index == 2)
            return calls;
        if (index == 3)
            return removals;
        if (index == 4)
        {
            uint64_t hash = 14695981039346656037ull;
            const auto *bytes = reinterpret_cast<const uint8_t *>(party.members);
            for (unsigned i = 0; i < sizeof(party.members); ++i)
                hash = (hash ^ bytes[i]) * 1099511628211ull;
            bytes = reinterpret_cast<const uint8_t *>(party.dirtyMembers);
            for (unsigned i = 0; i < sizeof(party.dirtyMembers); ++i)
                hash = (hash ^ bytes[i]) * 1099511628211ull;
            return hash;
        }
        return 0;
    }

    __declspec(dllexport) int Test_Reservation()
    {
        Test_Case(0, 255, 10, 0, 0);
        if (output != 4 || clients[4].state != 5 || removals != 0)
            return __LINE__;
        int next = -1;
        if (DW_PartyAtomicHost_AddAnonymousMember(&party, 42, &challenge, &next) != 1 || next != 0)
            return __LINE__;
        if (party.members[4].status != 2 || clients[4].state != 5 || removals != 0)
            return __LINE__;
        return 0;
    }

    __declspec(dllexport) int Test_ServerBounds()
    {
        Test_Case(0, 255, 10, 0, 0);
        party.members[4].status = 0;
        party.members[0].status = 0;
        DWJIP_ClientCount = 3;
        int next = -1;
        if (DW_PartyAtomicHost_AddAnonymousMember(&party, 42, &challenge, &next) != 1 || next != 0)
            return __LINE__;
        return 0;
    }
}
