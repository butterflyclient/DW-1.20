#include "com_debugstates.h"
#include "DW_ProgressionBindings.h"
#include "DW_PlaylistUI_Source.h"

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    extern void *gl_151868880;
    unsigned replay_rva_0148fce0(); // Original Sys_Milliseconds binding.
    double func_142084A10(void *, int); // lua_tonumber.
    int DW_MapVoting_UIState(char *, unsigned);
}

namespace
{
    unsigned s_lastCheck = 0;
    void *s_reportedVM = nullptr;
    bool s_reportedFailure = false;

    bool Execute(void *vm, const char *source, size_t size, double &result)
    {
        const auto top = DW_Progression_LuaTop(vm);
        auto error = DW_Progression_LuaLoad(vm, source, size, "ReplayDWPlaylistUI");
        if (!error)
            error = DW_Progression_LuaCall(vm, 0, 1, 0);
        if (!error)
            result = func_142084A10(vm, -1);
        DW_Progression_LuaSetTop(vm, top);
        return error == 0;
    }
}

extern "C" void DW_PlaylistUI_Frame()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
        return;
    const auto now = replay_rva_0148fce0();
    if (s_lastCheck && unsigned(now - s_lastCheck) < 1000)
        return;
    s_lastCheck = now;
    DW_Progression_LUILock();
    if (auto *vm = gl_151868880)
    {
        // Probe the current VM rather than caching its address: a replacement
        // VM may reuse that allocation after a native frontend reload.
        constexpr char probe[] =
            "local ready=MenuBuilder and MenuBuilder.IsTypeRegistered and "
            "MenuBuilder.IsTypeRegistered('ReplayDWPlaylistFillState'); "
            "if ready then MenuBuilder.m_types.replaydwplaylistfillstate().Refresh() end; "
            "return ready and 1 or 0";
        double installed = 0;
        bool ok = Execute(vm, probe, sizeof(probe) - 1, installed);
        if (ok && installed == 0)
            ok = Execute(vm, dwPlaylistUISource, sizeof(dwPlaylistUISource) - 1, installed);
        if (ok && installed == 1)
        {
            char voteState[1024]{}, update[1400]{};
            if (DW_MapVoting_UIState(voteState, sizeof(voteState)) > 0)
            {
                const int length = Com_sprintf(update, sizeof(update),
                    "MenuBuilder.m_types.replaydwplaylistfillstate().RefreshMapVote(%s); return 1", voteState);
                double refreshed = 0;
                if (length > 0 && unsigned(length) < sizeof(update))
                    ok = Execute(vm, update, unsigned(length), refreshed);
            }
            if (s_reportedVM != vm)
                Com_Printf(25, "DW_PLAYLIST_UI native playlist bot-fill toggle installed.\n");
            s_reportedVM = vm;
            s_reportedFailure = false;
        }
        else if (!ok && !s_reportedFailure)
        {
            Com_Printf(25, "DW_PLAYLIST_UI installation failed; waiting to retry.\n");
            s_reportedFailure = true;
        }
    }
    DW_Progression_LUIUnlock();
}
