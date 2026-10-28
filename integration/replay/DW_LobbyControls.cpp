// Backend controls enter through the native ruleset dvar window. Only the
// current lobby host submits native start/bot requests, on the main thread.
#include "com_debugstates.h"
#include "replay_dvar.h"

extern "C" void func_1413E9BE0(void *, const char *); // Dvar_SetString_Internal (as DW_ExecutableUpdate.cpp)
static dvar_t *s_customMapsDvar;

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_BotPolicy_Register();
    void DW_BotPolicy_Prepare(const void *);
    void DW_BotPolicy_BuildRoster(const void *, unsigned, unsigned);
    void DW_BotPolicy_ResetRoster();
    void DW_BotPolicy_CaptureRoster();
    void DW_MatchmakingAssignments_PrepareLaunch(const void *);
    void DW_PlaylistUI_Frame();
    const char *DW_MapAvailability_InstalledIds(); // " id1 id2 ... " of custom map packages
    void DW_MapAvailability_EnsureScanned();
    void DW_LocalBackend_LogLine(const char *); // DW_LocalBackend_Frame.cpp
    dvar_t *Dvar_RegisterString(const char *, const char *, uint32_t, const char *);
    uint64_t DW_LobbyControls_StartMatchInternalNative(void *, const void *);
    bool DW_LobbyControls_ReadyToLaunchNative(const void *, const void *);
    void replay_rva_00ca2070();                 // BG_GameStateInfo_ClearBotData
    bool replay_rva_01187fa0();                 // Lobby_IsInLobby
    void *replay_rva_01187ee0();                // Lobby_GetPartyData
    bool replay_rva_01189120(const void *);     // Party_AreWeHost
    bool replay_rva_0118dd00(const void *);     // Party_IsGameLobby
    void replay_rva_0119cfa0(void *, bool);     // PartyHost_RequestStartMatch
    void replay_rva_0119a5a0(void *);           // PartyHost_GamestateChanged
    unsigned replay_rva_0118c7d0(const void *); // Party_GetNumGameSlots
    void replay_rva_011916c0(void *, int);  // Party_SetNumGameSlots, including member index bits
    void replay_rva_00ca2370(int, int);     // BG_GameStateInfo_SetupBotsCountsPerTeamForScript
    void replay_rva_00ca1d20();             // BG_Bots_SelectBotsWithInitializedCount
    void replay_rva_01119b40(int, uint8_t); // BG_SetBotsTeamLimit
    unsigned replay_rva_0118ab60(const void *, int);      // Party_CountMembersEvenIfInactive
    unsigned replay_rva_0118ad10(const void *, int, int); // Party_CountTeamMembers
    void replay_rva_00ca2110();         // BG_GameStateInfo_EnableGameLaunchWithBots
    bool replay_rva_01528420();         // Live_IsInSystemlinkLobby
    int replay_rva_00ca1c50();          // BG_Bots_GetControllerIndex
    unsigned replay_rva_010cd460(int);  // Playlist_GetPlaylistIdForNum
    bool replay_rva_010cc6f0(unsigned); // Playlist_GetBotMatchMakingEnabled
    bool replay_rva_00ca2250();         // BG_GameStateInfo_IsBotMatchMakingDataInitialized
    bool replay_rva_00ca2270(unsigned); // BG_GameStateInfo_IsBotMemberPresent
    bool replay_rva_0118e020(const void *, unsigned); // Party_IsMemberIndexDataAvailable
    extern uint8_t replay_rva_0c27e4b0[];             // OnlineMatchmakerOmniscient::ms_instance
    extern dvar_t *gl_14D386820;                      // xblive_privatematch
    extern dvar_t *gl_14D386948;                      // playlist selector
    extern dvar_t *gl_14D386840;                      // party_maxplayers
    extern dvar_t *gl_14C796328;                      // party_teamCount
    extern dvar_t *DVARBOOL_onlinegame;
    extern void *gl_151868880;                           // LUI_luaVM, protected by native LUI lock
    void replay_rva_019bdad0();                          // LUI_EnterCriticalSection
    void replay_rva_019bedb0();                          // LUI_LeaveCriticalSection
    int replay_rva_020838b0(void *);                     // lua_gettop
    void replay_rva_020836e0(void *, int, const char *); // lua_getfield
    int replay_rva_02084ac0(void *, int);                // lua_type
    void replay_rva_02084100(void *, double);            // lua_pushnumber
    void replay_rva_02084510(void *, int, const char *); // lua_setfield
    void replay_rva_02084790(void *, int);               // lua_settop
    unsigned replay_rva_0148fce0();                      // Sys_Milliseconds
    int replay_rva_020839e0(void *, int);                // lua_isnumber
    int replay_rva_02089fb0(void *, const char *, ...);  // luaL_error
    int replay_rva_019ce9b0(void *, int);                // lui_tointeger32
    void replay_rva_02084120(void *, const char *);      // lua_pushstring
    void replay_rva_02083e80(void *, int);               // lua_pushboolean
    int replay_rva_00d66c20(int);                        // CL_Mgr_GetClientFromController
    void replay_rva_012a1830(int, const char *);         // LiveStorage_EnsureMaySetPersistentData
    int replay_rva_012a1eb0(int);                        // LiveStorage_GetActiveStatsSource
    bool replay_rva_015c7940(void *, int, int, int);     // CL_PlayerData_GetDDLBuffer
    void replay_rva_01acb360(void *, int, void *, void *, int); // LUI PlayerData member read
}

#include "DW_MapVoting.h"

namespace
{
    // Replay's complete registered type encoding. Script dvars use STRING (9),
    // while 7 is an unsigned 64-bit value, not a string pointer.
    enum class DvarType : uint8_t
    {
        Bool = 0,
        Float = 1,
        Vec2 = 2,
        Vec3 = 3,
        Vec4 = 4,
        Int = 5,
        Int64 = 6,
        UInt64 = 7,
        Enum = 8,
        String = 9,
        Color = 10,
        ColorXYZ = 11
    };
    dvar_t *s_start{}, *s_bots{}, *s_botCount{};
    dvar_t *s_autoFill{}, *s_autoActive{}, *s_autoComplete{}, *s_autoTarget{}, *s_autoRevision{}, *s_autoAck{};
    dvar_t *s_introVideos{}, *s_tutorialPrompts{};
    bool s_started = false, s_filled = false;
    unsigned s_luaPoll = 0;
    cmd_function_s s_fillCommand{};
    uint64_t s_lobby = 0;
    int s_commandBotCount = 0;
    unsigned s_requestStarted = 0;
    bool s_requestPending = false;
    bool s_autoRequest = false, s_autoWanted = false, s_autoRequestedComplete = false;
    bool s_autoClockValid = false, s_autoWasHost = false, s_autoNeedsClear = false;
    bool s_autoArmAcknowledged = false;
    unsigned s_autoStarted = 0, s_requestRevision = 0;
    unsigned s_autoRequestId = 0;
    unsigned s_filledCount = 0, s_filledHumans = 0, s_filledCapacity = 0;
    char s_requestDocument[16384]{};

    void SyncLobby()
    {
        // Native lobby identity at the target-build matchmaker field. A command
        // belongs to one matchmaking round, not a later lobby using this party.
        const auto lobby = *reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 79656);
        if (lobby == s_lobby)
            return;
        s_lobby = lobby;
        s_commandBotCount = 0;
        s_requestPending = false;
        s_autoRequest = false;
        s_autoWasHost = false;
        s_autoClockValid = false;
        s_autoWanted = false;
        s_autoNeedsClear = false;
        // Keep request tokens unique across allocations in this process. Old
        // publication dvars can outlive the native lobby identity by a frame.
        s_autoArmAcknowledged = false;
        s_filled = false;
        s_started = false;
        DW_BotPolicy_ResetRoster();
    }

    unsigned NativeBots(const void *party, unsigned capacity)
    {
        unsigned count = 0;
        if (replay_rva_00ca2250() && capacity <= 200)
            for (unsigned slot = 0; slot < capacity; ++slot)
                if (!replay_rva_0118e020(party, slot) && replay_rva_00ca2270(slot))
                    ++count;
        return count;
    }

    bool AutoFillPending(const void *party)
    {
        if (!DW_LocalBackend_IsEnabled() || !s_autoFill || !s_autoActive || !party ||
            !replay_rva_0118dd00(party) || replay_rva_01528420() ||
            Com_GameMode_GetActiveGameMode() == 3 || !DVARBOOL_onlinegame ||
            !DVARBOOL_onlinegame->current.enabled || !gl_14D386820 ||
            gl_14D386820->current.enabled)
            return false;
        if (!s_autoFill->current.enabled && !s_autoActive->current.enabled)
            return s_autoRequest && s_requestPending && s_autoNeedsClear;
        const unsigned capacity = replay_rva_0118c7d0(party);
        const unsigned humans = replay_rva_0118ab60(party, 1);
        if (!s_autoActive->current.enabled || !s_autoComplete->current.enabled ||
            !s_autoClockValid || !s_autoArmAcknowledged ||
            unsigned(replay_rva_0148fce0() - s_autoStarted) < 45000 ||
            s_requestPending || !s_filled || capacity > 200 || humans > capacity ||
            s_autoTarget->current.integer < 0 ||
            unsigned(s_autoTarget->current.integer) > capacity - humans ||
            s_filledHumans != humans || s_filledCapacity != capacity)
            return true;
        const unsigned target = unsigned(s_autoTarget->current.integer);
        return unsigned(s_botCount->current.integer) != target || NativeBots(party, capacity) != target;
    }

    void QueueAuto(unsigned count, bool complete)
    {
        // Accepted tokens belong to the lobby, including requests made by its
        // previous host. Keep our process token above that published high-water
        // mark; publication revisions alone do not acknowledge a request.
        const int accepted = s_autoAck->current.integer;
        if (accepted >= 0 && unsigned(accepted) > s_autoRequestId)
            s_autoRequestId = unsigned(accepted);
        if (s_autoRequestId == 0x7FFFFFFFU)
            return;
        s_commandBotCount = int(count);
        s_autoRequestedComplete = complete;
        s_autoRequest = true;
        s_requestPending = true;
        s_requestStarted = replay_rva_0148fce0();
        s_requestRevision = unsigned(s_autoRevision->current.integer);
        ++s_autoRequestId;
        *reinterpret_cast<bool *>(replay_rva_0c27e4b0 + 79636) = true;
        *reinterpret_cast<unsigned *>(replay_rva_0c27e4b0 + 79640) = 0;
    }

    void AcquireAutoFill(const void *party)
    {
        s_autoWasHost = true;
        s_autoClockValid = false;
        s_autoArmAcknowledged = false;
        s_requestPending = false;
        s_autoRequest = false;
        s_autoWanted = false;
        if (!s_autoActive->current.enabled)
            return;

        // The new host's checkbox is a local preference until it acquires this
        // lobby. Inherit the accepted active policy once, then ordinary later
        // checkbox changes remain explicit host requests.
        DvarValue on{};
        on.enabled = true;
        Dvar_SetVariant(s_autoFill, &on, 0);
        s_autoWanted = true;
        s_autoClockValid = true;
        s_autoStarted = replay_rva_0148fce0();
        const unsigned capacity = replay_rva_0118c7d0(party);
        const unsigned humans = replay_rva_0118ab60(party, 1);
        const int supplied = s_autoTarget->current.integer;
        const int count = s_botCount->current.integer;
        const bool complete = s_autoComplete->current.enabled && supplied >= 0 &&
                              count == supplied && capacity <= 200 && humans <= capacity &&
                              unsigned(supplied) <= capacity - humans;
        s_autoNeedsClear = !complete;
        s_filled = false;
        if (complete)
        {
            // A completed fill already passed the backend's timing fence. Keep
            // its count and roster; rebuild only if the native pool is missing.
            s_autoStarted -= 45000;
            s_autoArmAcknowledged = true;
            s_filledCount = unsigned(count);
            s_filledHumans = humans;
            s_filledCapacity = capacity;
            s_filled = NativeBots(party, capacity) == unsigned(count);
        }
        else
        {
            // Incomplete migration can restart the server's 30-second delay.
            // Arm with zero and wait for this host's exact accepted token before
            // applying a publication or growing the native pool.
            QueueAuto(0, false);
        }
    }

    void AutoFillFrame(const void *party)
    {
        const bool wanted = s_autoFill->current.enabled;
        const unsigned now = replay_rva_0148fce0();
        if (wanted && !s_autoWanted && !s_autoActive->current.enabled &&
            ((s_filled && s_botCount->current.integer > 0) ||
             (s_requestPending && !s_autoRequest)))
        {
            DvarValue off{};
            Dvar_SetVariant(s_autoFill, &off, 0);
            Com_Printf(25, "Fill lobby with bots: this lobby already has a manual bot request.\n");
            return;
        }
        if (wanted != s_autoWanted)
        {
            s_autoWanted = wanted;
            s_autoClockValid = wanted;
            s_autoArmAcknowledged = false;
            s_autoStarted = now;
            s_autoNeedsClear = true;
            s_filled = false;
            s_requestPending = false;
            QueueAuto(0, false);
        }
        if (!wanted)
        {
            if (s_autoActive->current.enabled && !s_requestPending)
                QueueAuto(0, false);
            return;
        }
        if (!s_autoClockValid)
        {
            s_autoClockValid = true;
            s_autoStarted = now;
            s_autoNeedsClear = true;
            s_filled = false;
            QueueAuto(0, false);
            return;
        }
        if (s_requestPending)
            return;
        if (!s_autoArmAcknowledged)
        {
            QueueAuto(0, false);
            return;
        }
        const unsigned elapsed = unsigned(now - s_autoStarted);
        if (!s_autoActive->current.enabled)
        {
            QueueAuto(0, false);
            return;
        }
        const int supplied = s_autoTarget->current.integer;
        const unsigned capacity = replay_rva_0118c7d0(party), humans = replay_rva_0118ab60(party, 1);
        if (supplied < 0 || capacity > 200 || humans > capacity || unsigned(supplied) > capacity - humans)
            return;
        const unsigned target = unsigned(supplied);
        const unsigned progress = elapsed <= 30000 ? 0 : elapsed >= 45000 ? 15000 : elapsed - 30000;
        const unsigned desired = target * progress / 15000;
        const unsigned acknowledged = unsigned(s_botCount->current.integer);
        if (s_autoComplete->current.enabled && elapsed >= 45000 && desired == acknowledged &&
            acknowledged == target && !s_filled)
            return; // Keep authoritative completion while rebuilding our native pool.
        const bool complete = elapsed >= 45000 && acknowledged == target && s_filled &&
                              s_filledHumans == humans && NativeBots(party, capacity) == target;
        if (desired != acknowledged || complete != s_autoComplete->current.enabled)
            QueueAuto(desired, complete);
    }

    void FillLobby_f()
    {
        if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread() || !s_botCount)
            return;
        if ((s_autoFill && s_autoFill->current.enabled) || (s_autoActive && s_autoActive->current.enabled))
        {
            Com_Printf(25, "fill_lobby: disable Fill lobby with bots before adding bots manually.\n");
            return;
        }
        unsigned requested = 0;
        const char *text = Cmd_Argc() == 2 ? Cmd_Argv(1) : nullptr;
        if (!text || !*text)
        {
            Com_Printf(25, "Usage: fill_lobby <number> (1-199 bots to add)\n");
            return;
        }
        for (const char *p = text; *p; ++p)
        {
            if (*p < '0' || *p > '9' || requested > 199 / 10)
            {
                Com_Printf(25, "fill_lobby: enter a whole number from 1 to 199.\n");
                return;
            }
            requested = requested * 10 + unsigned(*p - '0');
        }
        if (!requested || requested > 199)
        {
            Com_Printf(25, "fill_lobby: enter a whole number from 1 to 199.\n");
            return;
        }
        if (!Com_FrontEndScene_IsActive() || !replay_rva_01187fa0() || replay_rva_01528420() ||
            !DVARBOOL_onlinegame || !DVARBOOL_onlinegame->current.enabled || !gl_14D386820 ||
            gl_14D386820->current.enabled)
        {
            Com_Printf(25, "fill_lobby: run this in a public matchmaking lobby in the frontend.\n");
            return;
        }
        auto *party = replay_rva_01187ee0();
        if (!party || !replay_rva_0118dd00(party) || !replay_rva_01189120(party))
        {
            Com_Printf(25, "fill_lobby: only the current matchmaking host can add bots.\n");
            return;
        }
        SyncLobby();
        if (!s_lobby)
        {
            Com_Printf(25, "fill_lobby: wait until the matchmaking lobby is ready.\n");
            return;
        }
        const auto humans = replay_rva_0118ab60(party, 1);
        const auto capacity = replay_rva_0118c7d0(party);
        if (!humans || capacity > 200 || humans >= capacity)
        {
            Com_Printf(25, "fill_lobby: no playlist slots are available.\n");
            return;
        }
        unsigned bots = 0;
        if (replay_rva_00ca2250())
            for (unsigned i = 0; i < capacity; ++i)
                if (!replay_rva_0118e020(party, i) && replay_rva_00ca2270(i))
                    ++bots;
        // A second command before the next frame also includes the queued bots.
        if (s_requestPending && s_commandBotCount > int(bots))
            bots = unsigned(s_commandBotCount);
        if (bots >= capacity - humans)
        {
            Com_Printf(25, "fill_lobby: the lobby is already full.\n");
            return;
        }
        const auto available = capacity - humans - bots;
        const auto added = requested < available ? requested : available;
        s_commandBotCount = int(bots + added);
        s_autoRequest = false;
        s_requestPending = true;
        s_requestStarted = replay_rva_0148fce0();
        // Queue the SDK's existing authenticated 145/15 host document update.
        // The backend retains the count; no operator credential is used.
        *reinterpret_cast<bool *>(replay_rva_0c27e4b0 + 79636) = true;
        *reinterpret_cast<unsigned *>(replay_rva_0c27e4b0 + 79640) = 0;
        Com_Printf(
            25,
            "fill_lobby: adding %u bots (%u requested); %u bots total, playlist capacity %u.\n",
            added,
            requested,
            unsigned(s_commandBotCount),
            capacity);
    }

    void BotSetupLimits()
    {
        // The shipped GameSetupButtonsBots uses Lobby.GetMaxBotLimit, which
        // clamps these two Lua constants against real lobby slots. Change the
        // constants in the existing VM; no modified fastfile is required.
        const auto now = replay_rva_0148fce0();
        if (s_luaPoll && unsigned(now - s_luaPoll) < 1000)
            return;
        s_luaPoll = now;
        // Script-created BR dvars may appear only when its VM loads. Retain
        // their registered type and enforce the local two-player rule there too.
        if (auto *minimum = Dvar_FindVarByName("br_minplayers"))
        {
            DvarValue value{};
            if (static_cast<DvarType>(minimum->type) == DvarType::Int &&
                minimum->current.integer != 2)
            {
                value.integer = 2;
                Dvar_SetVariant(minimum, &value, 0);
            }
            else if (static_cast<DvarType>(minimum->type) == DvarType::String &&
                     minimum->current.string &&
                     (minimum->current.string[0] != '2' || minimum->current.string[1]))
            {
                value.string = "2";
                Dvar_SetVariant(minimum, &value, 0);
            }
        }
        if (auto *salePrice = Dvar_FindVarByName("lui_battlepass_tier_sale_price"))
        {
            if (static_cast<DvarType>(salePrice->type) == DvarType::Int &&
                salePrice->current.integer)
            {
                DvarValue free{};
                Dvar_SetVariant(salePrice, &free, 0);
            }
        }
        if (!gl_151868880)
            return;
        replay_rva_019bdad0();
        if (auto *vm = gl_151868880)
        {
            const auto top = replay_rva_020838b0(vm);
            replay_rva_020836e0(vm, -10002, "Lobby");
            if (replay_rva_02084ac0(vm, -1) == 5)
            {
                constexpr const char *keys[] = {"BotLimit", "BotLimitForSplitScreen"};
                for (const char *key : keys)
                {
                    replay_rva_02084100(vm, 200.0);
                    replay_rva_02084510(vm, -2, key);
                }
            }
            replay_rva_02084790(vm, top);
            replay_rva_020836e0(vm, -10002, "BATTLEPASS");
            if (replay_rva_02084ac0(vm, -1) == 5)
            {
                replay_rva_02084100(vm, 0.0);
                replay_rva_02084510(vm, -2, "SINGLE_TIER_COST");
            }
            replay_rva_02084790(vm, top);
        }
        replay_rva_019bedb0();
    }

    bool BotsRequested()
    {
        return DW_LocalBackend_IsEnabled() && s_botCount &&
               (s_botCount->current.integer > 0 || (s_autoFill && s_autoFill->current.enabled) ||
                (s_autoActive && s_autoActive->current.enabled));
    }
} // namespace

// Complete original eligibility predicate, retaining every native platform,
// online mode and controller check. A DW operator request additionally enables
// the shipped bot consumer for playlists whose BOTS flag is normally absent.
extern "C" bool func_140CA1C80()
{
    if (replay_rva_01528420() || gl_14D386820->current.enabled ||
        Com_GameMode_GetActiveGameMode() == 3 || !DVARBOOL_onlinegame->current.enabled)
        return false;
    const auto controller = replay_rva_00ca1c50();
    const auto playlist = replay_rva_010cd460(gl_14D386948->current.integer);
    return controller >= 0 && (BotsRequested() || replay_rva_010cc6f0(playlist));
}

extern "C" void DW_LobbyControls_Frame()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
        return;
    BotSetupLimits();
    if (!s_start)
    {
        DW_MapAvailability_EnsureScanned();
        Dvar_BeginPermanentRegistration();
        s_start = Dvar_RegisterInt(
            "replay_dw_forceStart", 0, 0, 1, 0, "DW operator native lobby start request");
        s_bots = Dvar_RegisterInt(
            "replay_dw_fillBots", 0, 0, 1, 0, "Legacy DW bot request; use replay_dw_botCount");
        s_botCount = Dvar_RegisterInt(
            "replay_dw_botCount", 0, 0, 199, 0, "DW operator number of native bots to add");
        s_autoFill = Dvar_RegisterBool("replay_dw_autoFillBots", false, 0,
                                      "Fill eligible lobby slots with native bots before starting");
        s_introVideos = Dvar_RegisterBool("lui_dwIntroVideos", false, 0,
                                          "Automatically show seasonal and mode introduction videos");
        s_tutorialPrompts = Dvar_RegisterBool("lui_dwTutorialPrompts", false, 0,
                                              "Automatically prompt for Warzone introduction and training");
        s_autoActive = Dvar_RegisterBool("replay_dw_autoFillBotsActive", false, 0,
                                        "Authoritative DW automatic bot fill state");
        s_autoComplete = Dvar_RegisterBool("replay_dw_autoFillBotsComplete", false, 0,
                                          "Authoritative DW native bot fill completion");
        s_autoTarget = Dvar_RegisterInt("replay_dw_autoFillBotTarget", 0, 0, 199, 0,
                                       "Eligible bot slots after human and No Fill reservations");
        s_autoRevision = Dvar_RegisterInt("replay_dw_autoFillRevision", 0, 0, 0x7FFFFFFF, 0,
                                         "Authoritative automatic fill publication revision");
        s_autoAck = Dvar_RegisterInt("replay_dw_autoFillAck", 0, 0, 0x7FFFFFFF, 0,
                                    "Accepted host automatic fill request token");
        // Com_GameInfo_Init scanned the custom map packages before any frame.
        s_customMapsDvar = Dvar_RegisterString("replay_dw_customMaps", DW_MapAvailability_InstalledIds(), 0,
                            "Installed custom map packages; playlists of other maps are hidden");
        DW_BotPolicy_Register();
        dwMapVoting::Register();
        Dvar_EndPermanentRegistration();
        Cmd_AddCommandInternal("fill_lobby", FillLobby_f, &s_fillCommand);
    }
    {
        // replay_dw_map_<id> (bool, true) per installed custom map package, for
        // the playlist UI's required-map guard. The string dvar above is fixed at
        // its first registration; these follow every later scan (owner 2026-10-16:
        // Nuketown TDM showed locked with the package installed).
        static char s_mapDvarNames[64][40];
        static unsigned s_mapDvarCount;
        static unsigned s_mapIdsLength = ~0u;
        const char *ids = DW_MapAvailability_InstalledIds();
        unsigned idsLength = 0;
        while (ids && ids[idsLength])
            ++idsLength;
        if (idsLength == s_mapIdsLength)
            ids = nullptr; // unchanged since the last frame
        else
        {
            s_mapIdsLength = idsLength;
            char line[1100] = "DW_CUSTOM_MAPS installed:";
            unsigned used = 25;
            for (unsigned i = 0; ids[i] && used + 1 < sizeof(line); ++i)
                line[used++] = ids[i];
            line[used] = 0;
            DW_LocalBackend_LogLine(line);
            // The scan can follow the first frame's registration (logged
            // 2026-10-16: an empty list first): keep the string current.
            if (s_customMapsDvar)
                func_1413E9BE0(s_customMapsDvar, ids);
        }
        for (unsigned at = 0; ids && ids[at];)
        {
            while (ids[at] == ' ')
                ++at;
            unsigned end = at;
            while (ids[end] && ids[end] != ' ')
                ++end;
            if (end > at && end - at < 24 && s_mapDvarCount < 64)
            {
                char name[40] = "replay_dw_map_";
                unsigned used = 14;
                for (unsigned i = at; i < end; ++i)
                    name[used++] = ids[i];
                name[used] = 0;
                bool known = false;
                for (unsigned i = 0; i < s_mapDvarCount && !known; ++i)
                {
                    unsigned c = 0;
                    while (name[c] && name[c] == s_mapDvarNames[i][c])
                        ++c;
                    known = !name[c] && !s_mapDvarNames[i][c];
                }
                if (!known)
                {
                    for (unsigned c = 0; c <= used; ++c)
                        s_mapDvarNames[s_mapDvarCount][c] = name[c];
                    Dvar_BeginPermanentRegistration();
                    Dvar_RegisterBool(s_mapDvarNames[s_mapDvarCount], true, 0,
                                      "Installed custom map package");
                    Dvar_EndPermanentRegistration();
                    ++s_mapDvarCount;
                }
            }
            at = end;
        }
    }
    if (!s_start->current.integer)
        s_started = false;
    if (!s_botCount->current.integer && !s_autoFill->current.enabled && !s_autoActive->current.enabled)
        s_filled = false;
    if (!Com_FrontEndScene_IsActive() || !replay_rva_01187fa0())
    {
        if (!Com_FrontEndScene_IsActive()) dwMapVoting::Suspend();
        DW_PlaylistUI_Frame();
        s_autoWasHost = false;
        s_autoClockValid = false;
        s_autoArmAcknowledged = false;
        return;
    }
    auto *party = replay_rva_01187ee0();
    dwMapVoting::Frame(party);
    DW_PlaylistUI_Frame();
    if (!party || !replay_rva_0118dd00(party) || !replay_rva_01189120(party))
    {
        s_autoWasHost = false;
        s_autoClockValid = false;
        s_autoArmAcknowledged = false;
        return;
    }
    SyncLobby();
    if (!s_lobby)
        return;
    if (s_requestPending)
    {
        const bool acknowledged = s_autoRequest
            ? unsigned(s_autoAck->current.integer) == s_autoRequestId &&
              s_autoActive->current.enabled == s_autoWanted
            : s_botCount->current.integer == s_commandBotCount;
        if (acknowledged)
        {
            s_requestPending = false;
            if (s_autoRequest && s_autoWanted && !s_commandBotCount && !s_autoRequestedComplete)
                s_autoArmAcknowledged = true;
            if (!s_autoRequest || s_filledCount != unsigned(s_botCount->current.integer))
                s_filled = false;
            Com_Printf(
                25, "fill_lobby: backend accepted %u native bots.\n", unsigned(s_botCount->current.integer));
        }
        else if (unsigned(replay_rva_0148fce0() - s_requestStarted) > 15000)
        {
            s_requestPending = false;
            Com_Printf(25, "fill_lobby: backend request timed out; no local-only fill applied.\n");
        }
    }
    if (gl_14D386820->current.enabled)
    {
        s_autoWasHost = false;
        s_autoClockValid = false;
        s_autoArmAcknowledged = false;
        if (gl_14D386840->current.integer != 200 || replay_rva_0118c7d0(party) != 200)
        {
            DvarValue maximum{};
            maximum.integer = 200;
            Dvar_SetVariant(gl_14D386840, &maximum, 0);
            replay_rva_011916c0(party, 200);
            replay_rva_0119a5a0(party);
        }
        return;
    }
    if (replay_rva_01528420() || Com_GameMode_GetActiveGameMode() == 3 ||
        !DVARBOOL_onlinegame || !DVARBOOL_onlinegame->current.enabled)
    {
        s_autoWasHost = false;
        s_autoClockValid = false;
        s_autoArmAcknowledged = false;
        return;
    }
    if (!s_autoWasHost)
        AcquireAutoFill(party);
    // Parsed backend assignments can precede a remote UDP party member.
    // Apply the current lobby's retained assignments before bot grouping.
    DW_MatchmakingAssignments_PrepareLaunch(party);
    AutoFillFrame(party);
    if (s_autoWanted && !s_autoArmAcknowledged)
        return;
    const auto currentHumans = replay_rva_0118ab60(party, 1);
    const auto currentCapacity = replay_rva_0118c7d0(party);
    const auto currentBots = unsigned(s_botCount->current.integer);
    if (s_filled && (s_filledCount != currentBots || s_filledHumans != currentHumans ||
                     s_filledCapacity != currentCapacity))
        s_filled = false;
    if (!currentBots && s_autoNeedsClear && !s_requestPending)
    {
        replay_rva_00ca2070();
        if (!s_autoWanted)
            DW_BotPolicy_ResetRoster();
        replay_rva_0119a5a0(party);
        s_autoNeedsClear = false;
        s_filled = true;
        s_filledCount = 0;
        s_filledHumans = currentHumans;
        s_filledCapacity = currentCapacity;
    }
    if (s_botCount->current.integer && !s_filled)
    {
        auto *teams = gl_14C796328;
        // Use the native neutral-team bot pool for BR's many-squad layout,
        // then restore its real team count before publishing the game state.
        // No synthetic party members or Demonware accounts are created.
        if (!teams || static_cast<DvarType>(teams->type) != DvarType::Int)
            return;
        const DvarValue saved = teams->current;
        const auto humans = replay_rva_0118ab60(party, 1);
        const auto capacity = replay_rva_0118c7d0(party);
        const auto requested = unsigned(s_botCount->current.integer);
        if (!humans || capacity > 200 || humans >= capacity || requested > capacity - humans)
            return;
        const auto total = humans + requested;
        auto allies = 0u, axis = 0u;
        if (saved.integer == 2)
        {
            allies = replay_rva_0118ad10(party, 2, 1);
            axis = replay_rva_0118ad10(party, 1, 1);
            if (allies > humans || axis > humans - allies)
                return;
        }
        if (saved.integer > 2)
        {
            DvarValue neutral{};
            Dvar_SetVariant(teams, &neutral, 0);
        }
        // Initialize only the native bot quotas and pool. Party slots and their
        // network encoding retain the playlist's actual capacity (e.g. 152 BR).
        DW_BotPolicy_CaptureRoster();
        replay_rva_00ca2070();
        replay_rva_00ca2370(int(total), saved.integer == 2 ? 2 : 0);
        if (saved.integer == 2)
        {
            for (unsigned unassigned = humans - allies - axis + requested; unassigned; --unassigned)
                if (allies <= axis)
                    ++allies;
                else
                    ++axis;
            replay_rva_01119b40(0, uint8_t(allies));
            replay_rva_01119b40(1, uint8_t(axis));
        }
        replay_rva_00ca1d20();
        DW_BotPolicy_BuildRoster(party, capacity, requested);
        if (saved.integer > 2)
            Dvar_SetVariant(teams, &saved, 0);
        DW_BotPolicy_Prepare(party);
        replay_rva_00ca2110();
        replay_rva_0119a5a0(party);
        DW_MatchmakingAssignments_PrepareLaunch(party);
        s_filled = true;
        s_filledCount = requested;
        s_filledHumans = humans;
        s_filledCapacity = capacity;
        Com_Printf(
            25,
            "DW_LOBBY_BOTS native pool prepared for %u bots; playlist capacity %u retained.\n",
            requested,
            capacity);
    }
    if (s_start->current.integer && !s_started && !AutoFillPending(party) && !dwMapVoting::Pending(party))
    {
        replay_rva_0119cfa0(party, true);
        s_started = true;
        Com_Printf(25, "DW_LOBBY_START native host start requested.\n");
    }
}

// The migration and lobby controls share Replay's original host-document SDK
// wrapper. Extend its bounded JSON before the SDK copies the caller's buffer.
extern "C" void DW_LobbyControls_HostDocument(uint64_t lobby,
                                              void *result,
                                              const char **document,
                                              unsigned *length)
{
    dwMapVoting::HostDocument(lobby, document, length);
    if (!s_requestPending || lobby != s_lobby || result != replay_rva_0c27e4b0 + 131864 ||
        !*reinterpret_cast<const bool *>(replay_rva_0c27e4b0 + 80128))
        return;
    if (s_autoRequest && (replay_rva_01528420() || Com_GameMode_GetActiveGameMode() == 3 ||
                          gl_14D386820->current.enabled || !DVARBOOL_onlinegame->current.enabled))
        return;
    if (!document || !*document || !length || *length < 3 ||
        *length > sizeof(s_requestDocument) - 192 || (*document)[*length - 1] != 0 ||
        (*document)[*length - 2] != '}')
    {
        s_requestPending = false;
        Com_Printf(25, "fill_lobby: host document has no room for the request.\n");
        return;
    }
    for (unsigned i = 0; i < *length - 2; ++i)
        s_requestDocument[i] = (*document)[i];
    const int added = s_autoRequest
        ? Com_sprintf(s_requestDocument + *length - 2,
                      sizeof(s_requestDocument) - (*length - 2),
                      ",\"dw_bot_count\":%u,\"dw_auto_fill_bots\":%s,\"dw_auto_fill_complete\":%s,\"dw_auto_fill_request\":%u}",
                      unsigned(s_commandBotCount), s_autoWanted ? "true" : "false",
                      s_autoRequestedComplete ? "true" : "false", s_autoRequestId)
        : Com_sprintf(s_requestDocument + *length - 2,
                      sizeof(s_requestDocument) - (*length - 2),
                      ",\"dw_bot_count\":%u}", unsigned(s_commandBotCount));
    if (added <= 0 || unsigned(added) >= sizeof(s_requestDocument) - (*length - 2))
    {
        s_requestPending = false;
        return;
    }
    *length = *length - 2 + unsigned(added) + 1;
    *document = s_requestDocument;
}

// Both native launch entry points retain complete recovered native bodies.
// The final internal guard also covers PartyHost_Frame's direct manual branch,
// which bypasses the ordinary readiness predicate and countdown.
extern "C" bool func_14119B0E0(void *party, const void *activeClient)
{
    DW_MatchmakingAssignments_PrepareLaunch(party);
    const bool nativeReady = DW_LobbyControls_ReadyToLaunchNative(party, activeClient);
    return nativeReady && !AutoFillPending(party) && !dwMapVoting::Pending(party);
}

extern "C" uint64_t func_14119E3D0(void *party, const void *activeClient)
{
    DW_MatchmakingAssignments_PrepareLaunch(party);
    return AutoFillPending(party) || dwMapVoting::Pending(party) ? uint64_t{0}
                                 : DW_LobbyControls_StartMatchInternalNative(party, activeClient);
}

extern "C" bool DW_LobbyControls_AutoFillEnabled()
{
    return s_autoFill && s_autoFill->current.enabled;
}

namespace
{
    // Stock ui/utils/onboarding.lua flag numbers read by automatic presentation.
    bool PresentationSuppressed(int tutorial)
    {
        const dvar_t *preference = nullptr;
        if ((tutorial >= 23 && tutorial <= 28) || tutorial == 42)
            preference = s_introVideos; // SEASON1..6_WATCH_FLAG, MAGMA_WATCHED_FLAG
        else if (tutorial == 33 || tutorial == 40 || tutorial == 44)
            preference = s_tutorialPrompts; // WARZONE_INTRODUCTION, _TUTORIAL_GAMEPLAY_INITIATED, PLUNDERTUTORIAL
        else
            return false;
        return DW_LocalBackend_IsEnabled() && !(preference && preference->current.enabled);
    }

    // CL_PlayerData_GetDDLBuffer output: the original frame's 0x30-byte window.
    struct PlayerDataBuffer
    {
        uint8_t header[0x10];
        void *ddl;
        uint8_t tail[0x18];
    };
} // namespace

// Complete shipped Engine tutorial-flag binding (LUI_CoD_LuaCall_IsTutorialCompleted_impl).
// After a match the frontend VM is replaced and the stock main menu runs its
// season video/reward sequence while it is built, before any Lua-side wrapper
// can be installed; a wrapper installed later also hid the real flag from the
// video's completion callback, so the saved flag was never set and the video
// repeated after every match. Disabled presentation flags therefore read as
// completed here, from the first frame. Saved flags and MarkCompleted are
// untouched; enabling the dvars restores the original reads.
extern "C" int func_1419F73C0(void *lua)
{
    constexpr const char *caller = "LUI_CoD_LuaCall_IsTutorialCompleted_impl";
    if (replay_rva_020838b0(lua) != 2)
        replay_rva_02089fb0(lua, "");
    if (!replay_rva_020839e0(lua, 1))
        replay_rva_02089fb0(lua, "");
    if (!replay_rva_020839e0(lua, 2))
        replay_rva_02089fb0(lua, "");
    const int controller = replay_rva_019ce9b0(lua, 1);
    int tutorial = replay_rva_019ce9b0(lua, 2);
    if (tutorial >= 64)
        replay_rva_02089fb0(lua, "");
    int results = 0;
    if (PresentationSuppressed(tutorial))
    {
        replay_rva_02083e80(lua, 1);
        results = 1;
    }
    else
    {
        replay_rva_012a1830(replay_rva_00d66c20(controller), caller);
        PlayerDataBuffer buffer{};
        if (!replay_rva_015c7940(&buffer, controller, replay_rva_012a1eb0(controller), 0))
            Com_Printf(14, "Tried to set PlayerData before we have downloaded player stats - %s\n", caller);
        else
        {
            const char *member = "mpTutorialLevel";
            if (tutorial > 31)
            {
                tutorial -= 32;
                member = "mpTutorialLevel2";
            }
            replay_rva_02084120(lua, member);
            replay_rva_01acb360(lua, 1, buffer.ddl, &buffer, 0);
            if (!replay_rva_020839e0(lua, -1))
                replay_rva_02089fb0(lua, "");
            const unsigned bits = unsigned(replay_rva_019ce9b0(lua, -1));
            replay_rva_02084790(lua, -2);
            replay_rva_02084790(lua, -2);
            replay_rva_02083e80(lua, int((bits >> (unsigned(tutorial) & 31)) & 1));
            results = 1;
        }
    }
    if (results > replay_rva_020838b0(lua))
        replay_rva_02089fb0(lua, "");
    return results;
}

extern "C" int DW_MapVoting_UIState(char *buffer, unsigned capacity)
{
    return dwMapVoting::UIState(buffer, capacity);
}
