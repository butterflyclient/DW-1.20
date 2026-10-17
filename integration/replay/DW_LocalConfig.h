#pragma once
#include <stdint.h>
extern "C"
{
    const char *DW_LocalConfig_Host();
    const char *DW_LocalConfig_PlayerName();
    const wchar_t *DW_LocalConfig_WideHost();
    const wchar_t *DW_LocalConfig_LoginPath();
    const wchar_t *DW_LocalConfig_Headers();
    const char *DW_LocalConfig_AuthUrl();
    const char *DW_LocalConfig_NativeAuthUrl();
    const char *DW_LocalConfig_LegacyUrl();
    const char *DW_LocalConfig_TestCommand();
    const char *DW_LocalConfig_TestEnabled();
    bool DW_LocalConfig_UnlockAll();
    bool DW_LocalConfig_BypassUpdateRestart();
    unsigned DW_LocalConfig_Rank();
    bool DW_LocalConfig_ResetProgression();
}

// Production endpoints require TLS; only exact loopback retains local HTTP.
inline bool DW_LocalConfig_UseTls(const char *host = DW_LocalConfig_Host())
{
    constexpr char loopback[] = "127.0.0.1";
    for (unsigned i = 0; i < sizeof(loopback); ++i)
        if (host[i] != loopback[i])
            return true;
    return false;
}
