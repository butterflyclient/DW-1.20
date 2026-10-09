// Isolated policy checks. Engine boundaries are modeled; no game is launched.
#include "../integration/replay/DW_LobbyControls.cpp"
#include <initializer_list>
#include <stdarg.h>

namespace
{
    bool enabled = true, mainThread = true, frontend = true, inLobby = true;
    bool host = true, gameLobby = true, systemlink = false, initialized = false;
    unsigned humans = 1, capacity = 12, existingBots = 0, setupTotal = 0;
    unsigned changed = 0, prepared = 0, maximumWrites = 0, teamLimits[2]{};
    unsigned humanAllies = 1, humanAxis = 0, setupCalls = 0;
    int argc = 2, registrationCount = 0;
    const char *argument = "4";
    dvar_t registered[3]{}, privateMatch{}, selector{}, maxPlayers{}, teams{}, online{};
    void (*command)() = nullptr;
    unsigned char party[8]{};

    void ResetRound()
    {
        ++*reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656);
        initialized = false;
        existingBots = 0;
        registered[2].current.integer = 0; // new authoritative lobby document
        DW_LobbyControls_Frame();
    }
} // namespace

extern "C"
{
    uint8_t replay_rva_0c27e4b0[132000]{};
    dvar_t *gl_14D386820 = &privateMatch, *gl_14D386948 = &selector;
    dvar_t *gl_14D386840 = &maxPlayers, *gl_14C796328 = &teams;
    dvar_t *DVARBOOL_onlinegame = &online;
    void *gl_151868880 = nullptr;

    bool DW_LocalBackend_IsEnabled()
    {
        return enabled;
    }

    bool Sys_IsMainThread()
    {
        return mainThread;
    }

    bool Com_FrontEndScene_IsActive()
    {
        return frontend;
    }

    int Com_GameMode_GetActiveGameMode()
    {
        return 2;
    }

    void replay_rva_00ca2070()
    {
        initialized = false;
        existingBots = 0;
    }

    void DW_BotPolicy_BuildRoster(const void *, unsigned, unsigned count)
    {
        existingBots = count;
    }

    int Com_sprintf(char *out, size_t size, const char *, ...)
    {
        const char *prefix = ",\"dw_bot_count\":";
        size_t used = 0;
        while (prefix[used])
        {
            if (used + 1 >= size)
                return -1;
            out[used] = prefix[used];
            ++used;
        }
        unsigned value = unsigned(s_commandBotCount), divisor = 100;
        while (divisor > 1 && value < divisor)
            divisor /= 10;
        do
        {
            if (used + 2 >= size)
                return -1;
            out[used++] = char('0' + value / divisor);
            value %= divisor;
            divisor /= 10;
        } while (divisor);
        out[used++] = '}';
        out[used] = 0;
        return int(used);
    }

    void DW_BotPolicy_Register() {}

    void DW_BotPolicy_Prepare(const void *)
    {
        ++prepared;
    }

    bool replay_rva_01187fa0()
    {
        return inLobby;
    }

    void *replay_rva_01187ee0()
    {
        return party;
    }

    bool replay_rva_01189120(const void *)
    {
        return host;
    }

    bool replay_rva_0118dd00(const void *)
    {
        return gameLobby;
    }

    void replay_rva_0119cfa0(void *, bool) {}

    void replay_rva_0119a5a0(void *)
    {
        ++changed;
    }

    unsigned replay_rva_0118c7d0(const void *)
    {
        return capacity;
    }

    void replay_rva_011916c0(void *, int)
    {
        ++maximumWrites;
    }

    void replay_rva_00ca2370(int total, int)
    {
        setupTotal = total;
        ++setupCalls;
    }

    void replay_rva_00ca1d20()
    {
        existingBots = setupTotal - humans;
        initialized = true;
    }

    void replay_rva_01119b40(int team, uint8_t total)
    {
        teamLimits[team] = total;
    }

    unsigned replay_rva_0118ab60(const void *, int)
    {
        return humans;
    }

    unsigned replay_rva_0118ad10(const void *, int team, int)
    {
        return team == 2 ? humanAllies : humanAxis;
    }

    void replay_rva_00ca2110() {}

    bool replay_rva_01528420()
    {
        return systemlink;
    }

    int replay_rva_00ca1c50()
    {
        return 0;
    }

    unsigned replay_rva_010cd460(int)
    {
        return 1;
    }

    bool replay_rva_010cc6f0(unsigned)
    {
        return false;
    }

    bool replay_rva_00ca2250()
    {
        return initialized;
    }

    bool replay_rva_00ca2270(unsigned index)
    {
        return index < humans + existingBots;
    }

    bool replay_rva_0118e020(const void *, unsigned index)
    {
        return index < humans;
    }

    void replay_rva_019bdad0() {}

    void replay_rva_019bedb0() {}

    int replay_rva_020838b0(void *)
    {
        return 0;
    }

    void replay_rva_020836e0(void *, int, const char *) {}

    int replay_rva_02084ac0(void *, int)
    {
        return 0;
    }

    void replay_rva_02084100(void *, double) {}

    void replay_rva_02084510(void *, int, const char *) {}

    void replay_rva_02084790(void *, int) {}

    unsigned replay_rva_0148fce0()
    {
        return 1;
    }

    int Cmd_Argc()
    {
        return argc;
    }

    const char *Cmd_Argv(int)
    {
        return argument;
    }

    void Cmd_AddCommandInternal(const char *, void (*callback)(), cmd_function_s *)
    {
        command = callback;
    }

    void Com_Printf(int, const char *, ...) {}

    void Dvar_BeginPermanentRegistration() {}

    void Dvar_EndPermanentRegistration() {}

    dvar_t *Dvar_RegisterInt(
        const char *name, int32_t value, int32_t minimum, int32_t maximum, uint32_t, const char *)
    {
        auto &dvar = registered[registrationCount++];
        dvar.name = name;
        dvar.type = 5;
        dvar.current.integer = value;
        dvar.domain.integer = {minimum, maximum};
        return &dvar;
    }

    dvar_t *Dvar_FindVarByName(const char *)
    {
        return nullptr;
    }

    void Dvar_SetVariant(dvar_t *dvar, const DvarValue *value, int)
    {
        dvar->current = *value;
    }
}

#define CHECK(expression)                                                                          \
    if (!(expression))                                                                             \
    return __LINE__

extern "C" __declspec(dllexport) int Test_Run()
{
    online.current.enabled = true;
    teams.type = 5;
    teams.current.integer = 2;
    maxPlayers.current.integer = 12;
    *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656) = 1;
    *reinterpret_cast<bool *>(replay_rva_0c27e4b0 + 80128) = true;
    DW_LobbyControls_Frame();
    CHECK(command && registrationCount == 3);
    for (const char *bad : {"", "0", "-1", "+2", "1.5", "199x", "200", "99999999999999"})
    {
        argument = bad;
        command();
        CHECK(registered[2].current.integer == 0 && setupCalls == 0);
    }
    argc = 3;
    argument = "4";
    command();
    CHECK(!registered[2].current.integer);
    argc = 2;
    for (bool *gate : {&enabled, &mainThread, &frontend, &inLobby, &host, &gameLobby})
    {
        *gate = false;
        command();
        *gate = true;
        CHECK(!registered[2].current.integer);
    }
    for (bool *gate : {&privateMatch.current.enabled, &systemlink})
    {
        *gate = true;
        command();
        *gate = false;
        CHECK(!registered[2].current.integer);
    }
    command();
    CHECK(!registered[2].current.integer && s_commandBotCount == 4);
    argument = "2";
    command();
    CHECK(!registered[2].current.integer && s_commandBotCount == 6); // queued additions
    registered[2].current.integer = s_commandBotCount;               // accepted backend document
    DW_LobbyControls_Frame();
    CHECK(existingBots == 6 && setupTotal == 7 && teamLimits[0] == 4 && teamLimits[1] == 3);
    CHECK(changed == 1 && prepared == 1 && !maximumWrites && capacity == 12);
    DW_LobbyControls_Frame();
    CHECK(setupCalls == 1);
    argument = "199";
    command();
    registered[2].current.integer = s_commandBotCount; // accepted backend document
    DW_LobbyControls_Frame();
    CHECK(existingBots == 11 && setupTotal == 12 && capacity == 12);
    command();
    DW_LobbyControls_Frame();
    CHECK(setupCalls == 2); // full lobby is a no-op
    ResetRound();
    CHECK(!registered[2].current.integer);
    humans = 2;
    humanAllies = 1;
    humanAxis = 1;
    capacity = 152;
    teams.current.integer = 51;
    argument = "20";
    command();
    registered[2].current.integer = s_commandBotCount; // accepted backend document
    DW_LobbyControls_Frame();
    CHECK(existingBots == 20 && setupTotal == 22 && teams.current.integer == 51);
    CHECK(capacity == 152 && !maximumWrites && prepared == 3);
    ResetRound();
    capacity = 201;
    command();
    CHECK(!registered[2].current.integer);
    capacity = 12;
    humans = 12;
    command();
    CHECK(!registered[2].current.integer);
    humans = 2;
    teams.current.integer = 2;
    humanAllies = 3;
    argument = "1";
    command();
    registered[2].current.integer = s_commandBotCount; // accepted backend document
    const auto previous = setupCalls;
    DW_LobbyControls_Frame();
    CHECK(setupCalls == previous && teams.current.integer == 2);
    return 0;
}
