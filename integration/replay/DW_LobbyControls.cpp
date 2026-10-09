// Backend controls enter through the native ruleset dvar window. Only the
// current lobby host submits native start/bot requests, on the main thread.
#include "com_debugstates.h"
#include "replay_dvar.h"

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_BotPolicy_Register();
    void DW_BotPolicy_Prepare(const void *);
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
    extern dvar_t *gl_14D386820;        // xblive_privatematch
    extern dvar_t *gl_14D386948;        // playlist selector
    extern dvar_t *gl_14D386840;        // party_maxplayers
    extern dvar_t *gl_14C796328;        // party_teamCount
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
}

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
    bool s_started = false, s_filled = false;
    unsigned s_luaPoll = 0;

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
        return DW_LocalBackend_IsEnabled() && s_botCount && s_botCount->current.integer > 0;
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
        Dvar_BeginPermanentRegistration();
        s_start = Dvar_RegisterInt(
            "replay_dw_forceStart", 0, 0, 1, 0, "DW operator native lobby start request");
        s_bots = Dvar_RegisterInt(
            "replay_dw_fillBots", 0, 0, 1, 0, "Legacy DW bot request; use replay_dw_botCount");
        s_botCount = Dvar_RegisterInt(
            "replay_dw_botCount", 0, 0, 199, 0, "DW operator number of native bots to add");
        DW_BotPolicy_Register();
        Dvar_EndPermanentRegistration();
    }
    if (!s_start->current.integer)
        s_started = false;
    if (!s_botCount->current.integer)
        s_filled = false;
    if (!Com_FrontEndScene_IsActive() || !replay_rva_01187fa0())
        return;
    auto *party = replay_rva_01187ee0();
    if (!party || !replay_rva_0118dd00(party) || !replay_rva_01189120(party))
        return;
    if (gl_14D386820->current.enabled)
    {
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
        if (saved.integer > 2)
        {
            DvarValue neutral{};
            Dvar_SetVariant(teams, &neutral, 0);
        }
        // Initialize only the native bot quotas and pool. Party slots and their
        // network encoding retain the playlist's actual capacity (e.g. 152 BR).
        replay_rva_00ca2370(int(total), saved.integer == 2 ? 2 : 0);
        if (saved.integer == 2)
        {
            auto allies = replay_rva_0118ad10(party, 2, 1);
            auto axis = replay_rva_0118ad10(party, 1, 1);
            if (allies + axis > humans)
                return;
            for (unsigned unassigned = humans - allies - axis + requested; unassigned; --unassigned)
                if (allies <= axis)
                    ++allies;
                else
                    ++axis;
            replay_rva_01119b40(0, uint8_t(allies));
            replay_rva_01119b40(1, uint8_t(axis));
        }
        replay_rva_00ca1d20();
        if (saved.integer > 2)
            Dvar_SetVariant(teams, &saved, 0);
        DW_BotPolicy_Prepare(party);
        replay_rva_00ca2110();
        replay_rva_0119a5a0(party);
        s_filled = true;
        Com_Printf(
            25,
            "DW_LOBBY_BOTS native pool prepared for %u bots; playlist capacity %u retained.\n",
            requested,
            capacity);
    }
    if (s_start->current.integer && !s_started)
    {
        replay_rva_0119cfa0(party, true);
        s_started = true;
        Com_Printf(25, "DW_LOBBY_START native host start requested.\n");
    }
}
