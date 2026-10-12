#include "DW_JoinInProgressBindings.h"
#include "replay_dvar.h"
#include <stddef.h>
#include <stdint.h>

namespace DWJoin
{
#pragma pack(push, 1)

    struct Challenge
    {
        uint32_t first;
        uint16_t last;
    };

#pragma pack(pop)

    // Complete 488-byte Replay party member. Anonymous challenge identity is
    // distinct from the player XUID installed when the reservation commits.
    struct Member
    {
        uint8_t prefix[52];
        char name[36];
        uint8_t opaque88[124];
        uint32_t challengeFirst;
        uint16_t challengeLast;
        uint8_t opaque218[6];
        uint64_t challengeXuid;
        uint8_t opaque232[32];
        uint32_t reservedAt;
        uint8_t opaque268[120];
        int32_t subparty, team, squad;
        uint8_t opaque400[2];
        uint8_t status;
        uint8_t opaque403[5];
        uint64_t xuid;
        uint8_t opaque416[72];
    };

    struct PartyView
    {
        uint8_t prefix[2192];
        Member members[200];
        uint8_t toName[311056 - 2192 - sizeof(Member) * 200];
        const char *name;
        uint8_t toDirty[311164 - 311064];
        uint32_t dirtyMembers[7];
    };

    struct ClientView
    {
        uint8_t prefix[8];
        uint8_t state;
    };

    static_assert(sizeof(Challenge) == 6);
    static_assert(sizeof(Member) == 488);
    static_assert(offsetof(Member, challengeFirst) == 212);
    static_assert(offsetof(Member, challengeLast) == 216);
    static_assert(offsetof(Member, challengeXuid) == 224);
    static_assert(offsetof(Member, reservedAt) == 264);
    static_assert(offsetof(Member, status) == 402);
    static_assert(offsetof(Member, xuid) == 408);
    static_assert(offsetof(PartyView, members) == 2192);
    static_assert(offsetof(PartyView, name) == 311056);
    static_assert(offsetof(PartyView, dirtyMembers) == 311164);
    static_assert(offsetof(ClientView, state) == 8);
} // namespace DWJoin

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    int DWJIP_GameSlots(const void *);
    bool DWJIP_GameLobby(const void *);
    unsigned DWJIP_PlaylistId(int);
    int DWJIP_MaxHumanPlayers(unsigned);
    int DWJIP_OldestSlot(const void *, int, int);
    bool DWJIP_LocalServerRunning();
    bool DWJIP_ServerLoaded();
    bool DWJIP_AreWeHost(const void *);
    const void *DWJIP_ServerLobby();
    bool DWJIP_IsBot(unsigned);
    void DWJIP_Print(int, const char *, ...);
    const char *DWJIP_XuidString(const uint64_t *);
    void DWJIP_RemoveMember(void *, int, int, const char *, int);
    void *DWJIP_XuidAssign(uint64_t *, const uint64_t *);
    unsigned DWJIP_Milliseconds();
    void *DWJIP_Zero(void *, int, size_t);
    extern dvar_t *DWJIP_PrivateMatch, *DWJIP_Playlist;
    extern dvar_t *DWJIP_AnonymousDuration, *DWJIP_ZombieDuration, *DWJIP_ConnectingDuration;
    extern unsigned DWJIP_ClientCount;
    extern DWJoin::ClientView *DWJIP_Clients[];
}

namespace
{
    int preferredBot(const DWJoin::PartyView *party, int limit)
    {
        if (!DW_LocalBackend_IsEnabled() || DWJIP_PrivateMatch->current.enabled ||
            !DWJIP_GameLobby(party) || !DWJIP_LocalServerRunning() || !DWJIP_ServerLoaded() ||
            !DWJIP_AreWeHost(party) || DWJIP_ServerLobby() != party)
            return -1;
        for (unsigned index = 0;
             index < unsigned(limit) && index < 200 && index < DWJIP_ClientCount;
             ++index)
        {
            const auto *client = DWJIP_Clients[index];
            if (party->members[index].status == 0 && client && client->state > 2 &&
                DWJIP_IsBot(index))
                return int(index);
        }
        return -1;
    }
} // namespace

// Complete original AddAnonymousMember. Reserve the connected bot's party
// slot; the unchanged authenticated DirectConnect path later tears it down.
extern "C" int DW_PartyAtomicHost_AddAnonymousMember(DWJoin::PartyView *party,
                                                     uint64_t requestXuid,
                                                     const DWJoin::Challenge *challenge,
                                                     int *outIndex)
{
    int limit = DWJIP_GameSlots(party);
    if (DWJIP_GameLobby(party) && !DWJIP_PrivateMatch->current.enabled)
    {
        const int maximum =
            DWJIP_MaxHumanPlayers(DWJIP_PlaylistId(DWJIP_Playlist->current.integer));
        if (maximum && maximum < limit)
            limit = maximum;
    }
    int slot = limit > 0 ? preferredBot(party, limit) : -1;
    if (slot < 0)
        for (int index = 0; index < limit; ++index)
            if (party->members[index].status == 0)
            {
                slot = index;
                break;
            }
    if (slot < 0)
    {
        slot = DWJIP_OldestSlot(party, 2, DWJIP_AnonymousDuration->current.integer);
        if (slot < 0)
        {
            slot = DWJIP_OldestSlot(party, 3, DWJIP_ZombieDuration->current.integer);
            if (slot < 0 && (!DWJIP_GameLobby(party) || !DWJIP_LocalServerRunning()))
                slot = DWJIP_OldestSlot(party, 4, DWJIP_ConnectingDuration->current.integer);
        }
        if (slot < 0)
        {
            DWJIP_Print(25,
                        "[%s] PartyHost - AddAnonymousMember - Rejecting incoming party member "
                        "because the party is full (no empty, anonymous, or zombie slots)\n",
                        party->name);
            return 30;
        }
        const unsigned status = party->members[slot].status;
        if (status)
            DWJIP_Print(25,
                        "[%s] PartyHost - PartyAtomicHost_FindOldestUsedSlotForAnonymousMember - "
                        "Clearing out slot %i with status %i for new player\n",
                        party->name,
                        slot,
                        status);
        DWJIP_RemoveMember(party, slot, 0, "", 0);
    }
    DWJIP_Print(25,
                "[%s] PartyHost - AddAnonymousMember - Reserving slot %i for challenge %s (%s)\n",
                party->name,
                slot,
                reinterpret_cast<const char *>(challenge),
                DWJIP_XuidString(&requestXuid));
    auto &member = party->members[slot];
    DWJIP_Zero(&member, 0, sizeof(member));
    member.status = 2;
    member.challengeFirst = challenge->first;
    member.challengeLast = challenge->last;
    DWJIP_XuidAssign(&member.challengeXuid, &requestXuid);
    member.reservedAt = DWJIP_Milliseconds();
    if (DWJIP_GameLobby(party))
        party->dirtyMembers[unsigned(slot) >> 5] &= ~(0x80000000u >> (unsigned(slot) & 31));
    if (outIndex)
        *outIndex = slot;
    return 1;
}
