// Authored source is imported through the Replay workstation revision API.
// Only the *_dw.exe build selects local endpoints. Other builds retain native values.
#include "com_debugstates.h"
#include "replay_dvar.h"
#include "DW_LocalConfig.h"
#include "DW_LocalProgression.h"
#include "DW_NetworkDiagnostics.h"

extern "C"
{
    void DW_ExecutableUpdate_Frame();
    void DW_LobbyControls_Frame();
    void DW_WeaponInspectInput_Frame();
    void DW_CustomOperators_Frame();
    void DW_SlideView_Init();
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *, char *, unsigned long);
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
    __declspec(dllimport) void *__stdcall CreateThread(
        void *, size_t, unsigned long(__stdcall *)(void *), void *, unsigned long, unsigned long *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) void *__stdcall CreateFileA(
        const char *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall WriteFile(
        void *, const void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) uint64_t __stdcall GetTickCount64();
    __declspec(dllimport) unsigned long __stdcall GetLastError();
    __declspec(dllimport) unsigned long __stdcall GetCurrentProcessId();
}

// The native Replay getter instructions and buildAuthReq access establish this
// configuration prefix. Port getters originally read +0x424 / +0x826; the
// corresponding native address arrays occupy the preceding 1024 bytes.
#pragma pack(push, 1)

struct DWReplayLoginConfigPrefix
{
    unsigned char platformAndTitle[36];
    char authAddress[1024];
    uint16_t authPort;
    char lobbyAddress[1024];
    uint16_t lobbyPort;
};

#pragma pack(pop)
static_assert(offsetof(DWReplayLoginConfigPrefix, authAddress) == 36);
static_assert(offsetof(DWReplayLoginConfigPrefix, authPort) == 1060);
static_assert(offsetof(DWReplayLoginConfigPrefix, lobbyAddress) == 1062);
static_assert(offsetof(DWReplayLoginConfigPrefix, lobbyPort) == 2086);
static_assert(sizeof(DWReplayLoginConfigPrefix) == 2088);

namespace
{
    unsigned s_mode = 0;  // 0 unchecked, 1 native, 2 local DW build
    unsigned s_probe = 0; // 0 idle, 1 running, 2 transport ready, 3 unavailable
    unsigned s_reported = 0;
    bool s_registered = false;
    cmd_function_s s_statusCommand{}, s_probeCommand{};
    char s_response[2048]{};

    bool Contains(const char *text, const char *needle)
    {
        for (; *text; ++text)
        {
            unsigned i = 0;
            while (needle[i] && text[i] && text[i] == needle[i])
                ++i;
            if (!needle[i])
                return true;
        }
        return false;
    }

    void WriteLog(const char *message)
    {
        void *file = CreateFileA("replay-dw-client.log", 4, 3, nullptr, 4, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return;
        unsigned long written = 0;
        unsigned length = 0;
        while (message[length])
            ++length;
        WriteFile(file, message, length, &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }

    void WriteEndpointLog(const char *prefix, const char *suffix)
    {
        char message[256]{};
        const auto *host = DW_LocalConfig_Host();
        const char *parts[] = {prefix, *host ? host : "<invalid-config>", suffix};
        unsigned used = 0;
        for (const auto *part : parts)
            for (; *part && used + 1 < sizeof(message); ++part)
                message[used++] = *part;
        WriteLog(message);
    }

    unsigned long __stdcall ProbeThread(void *)
    {
        using Handle = void *;
        using Open = Handle(__stdcall *)(
            const wchar_t *, unsigned long, const wchar_t *, const wchar_t *, unsigned long);
        using Connect = Handle(__stdcall *)(Handle, const wchar_t *, unsigned short, unsigned long);
        using Request = Handle(__stdcall *)(Handle,
                                            const wchar_t *,
                                            const wchar_t *,
                                            const wchar_t *,
                                            const wchar_t *,
                                            const wchar_t **,
                                            unsigned long);
        using Timeouts = int(__stdcall *)(Handle, int, int, int, int);
        using Send = int(__stdcall *)(Handle,
                                      const wchar_t *,
                                      unsigned long,
                                      void *,
                                      unsigned long,
                                      unsigned long,
                                      uintptr_t);
        using Receive = int(__stdcall *)(Handle, void *);
        using Headers = int(__stdcall *)(
            Handle, unsigned long, const wchar_t *, void *, unsigned long *, unsigned long *);
        using Read = int(__stdcall *)(Handle, void *, unsigned long, unsigned long *);
        using Close = int(__stdcall *)(Handle);
        using Stage = DWNetworkDiagnostics::Stage;
        const bool tls = DW_LocalConfig_UseTls();
        DWNetworkDiagnostics::Request diagnostic(
            DWNetworkDiagnostics::Operation::Health,
            DW_LocalConfig_Host(), tls ? 8443 : 8085, WriteLog, GetTickCount64,
            GetCurrentProcessId());
        bool ok = false;
        unsigned long error = 0, status = 0;
        unsigned used = 0;
        auto checked = [&](int success)
        {
            if (!success)
                error = GetLastError();
            diagnostic.End(success != 0, error, status, used, 0);
            return success != 0;
        };
        diagnostic.Begin(Stage::LoadLibrary);
        void *library = LoadLibraryA("winhttp.dll");
        checked(library != nullptr);
        s_response[0] = 0;
        if (library)
        {
            diagnostic.Begin(Stage::ResolveApi);
            auto open = reinterpret_cast<Open>(GetProcAddress(library, "WinHttpOpen"));
            auto connect = reinterpret_cast<Connect>(GetProcAddress(library, "WinHttpConnect"));
            auto request = reinterpret_cast<Request>(GetProcAddress(library, "WinHttpOpenRequest"));
            auto timeouts =
                reinterpret_cast<Timeouts>(GetProcAddress(library, "WinHttpSetTimeouts"));
            auto send = reinterpret_cast<Send>(GetProcAddress(library, "WinHttpSendRequest"));
            auto receive =
                reinterpret_cast<Receive>(GetProcAddress(library, "WinHttpReceiveResponse"));
            auto headers =
                reinterpret_cast<Headers>(GetProcAddress(library, "WinHttpQueryHeaders"));
            auto read = reinterpret_cast<Read>(GetProcAddress(library, "WinHttpReadData"));
            auto close = reinterpret_cast<Close>(GetProcAddress(library, "WinHttpCloseHandle"));
            using Option = int (__stdcall *)(Handle, unsigned long, void *, unsigned long);
            auto option = reinterpret_cast<Option>(GetProcAddress(library, "WinHttpSetOption"));
            auto callback = reinterpret_cast<DWNetworkDiagnostics::SetCallback>(
                GetProcAddress(library, "WinHttpSetStatusCallback"));
            unsigned long redirectPolicy = 0; // WINHTTP_OPTION_REDIRECT_POLICY_NEVER
            if (checked(open && connect && request && timeouts && send && receive && headers &&
                        read && close && option))
            {
                Handle session = nullptr;
                Handle connection = nullptr;
                Handle message = nullptr;
                do
                {
                    diagnostic.Begin(Stage::Open);
                    session = open(L"IW8-Replay-LocalDW/1", 1, nullptr, nullptr, 0);
                    if (!checked(session != nullptr))
                        break;
                    diagnostic.Begin(Stage::Timeouts);
                    if (!checked(timeouts(session, 1000, 1000, 1000, 1000)))
                        break;
                    diagnostic.Begin(Stage::Connect);
                    connection = connect(session, DW_LocalConfig_WideHost(), tls ? 8443 : 8085, 0);
                    if (!checked(connection != nullptr))
                        break;
                    diagnostic.Begin(Stage::OpenRequest);
                    message = request(connection, L"GET", L"/health", nullptr, nullptr, nullptr,
                                      tls ? 0x00800000 : 0);
                    if (!checked(message != nullptr))
                        break;
                    diagnostic.Attach(message, option, callback);
                    diagnostic.Begin(Stage::RedirectPolicy);
                    if (!checked(option(message, 88, &redirectPolicy, sizeof(redirectPolicy))))
                        break;
                    diagnostic.Begin(Stage::Send);
                    if (!checked(send(message, nullptr, 0, nullptr, 0, 0, diagnostic.Context())))
                        break;
                    diagnostic.Begin(Stage::Receive);
                    if (!checked(receive(message, nullptr)))
                        break;
                    diagnostic.Begin(Stage::QueryStatus);
                    unsigned long statusSize = sizeof(status);
                    if (!checked(headers(message, 0x20000013, nullptr, &status, &statusSize, nullptr)))
                        break;
                    diagnostic.Begin(Stage::HttpStatus);
                    diagnostic.End(status == 200, 0, status, used, 0);
                    if (status != 200)
                        break;

                    bool complete = false;
                    while (used < sizeof(s_response) - 1)
                    {
                        unsigned long received = 0;
                        diagnostic.Begin(Stage::Read);
                        const bool readOk = checked(read(
                            message, s_response + used,
                            static_cast<unsigned long>(sizeof(s_response) - 1 - used), &received));
                        if (!readOk)
                            break;
                        if (!received)
                        {
                            complete = true;
                            break;
                        }
                        used += received;
                    }
                    s_response[used] = 0;
                    ok = complete && Contains(s_response, "\"server\":\"iw8-dw\"") &&
                         Contains(s_response, "\"build\":\"replay120\"") &&
                         Contains(s_response, "\"stage\":\"transport-ready\"");
                    if (!error)
                    {
                        diagnostic.Begin(Stage::ValidateBody);
                        diagnostic.End(ok, 0, status, used, 0);
                    }
                } while (false);
                diagnostic.Detach();
                if (message)
                    close(message);
                if (connection)
                    close(connection);
                if (session)
                    close(session);
            }
            FreeLibrary(library);
        }
        diagnostic.Complete(ok, error, status, used, 0, 0);
        WriteEndpointLog(ok ? "DW_LOCAL_PROBE_OK host=" : "DW_LOCAL_PROBE_FAILED host=",
                         ok ? " backend health reached; native authentication/tasks pending"
                            : " backend health unavailable; check this endpoint's server "
                              "and network access");
        __atomic_store_n(&s_probe, ok ? 2U : 3U, __ATOMIC_RELEASE);
        return 0;
    }
} // namespace

extern "C" bool DW_LocalBackend_IsEnabled()
{
    unsigned mode = __atomic_load_n(&s_mode, __ATOMIC_ACQUIRE);
    if (!mode)
    {
        char path[1024]{};
        const unsigned long length = GetModuleFileNameA(nullptr, path, sizeof(path));
        bool enabled = length >= 7 && length < sizeof(path);
        constexpr char suffix[] = "_dw.exe";
        for (unsigned i = 0; enabled && i < 7; ++i)
        {
            char c = path[length - 7 + i];
            if (c >= 'A' && c <= 'Z')
                c += 'a' - 'A';
            enabled = c == suffix[i];
        }
        mode = enabled ? 2U : 1U;
        __atomic_store_n(&s_mode, mode, __ATOMIC_RELEASE);
    }
    return mode == 2;
}

extern "C" const char *DW_LocalBackend_GetAuthAddress(const void *nativeConfig)
{
    // Original buildAuthReq tests this getter before it asks for the port. An
    // empty native address selects a generated production hostname for that
    // entire request, so the local host must be selected at this first read.
    // DW_LocalConfig_Host owns the bounded, validated, NUL-terminated INI host.
    return DW_LocalBackend_IsEnabled()
               ? DW_LocalConfig_Host()
               : static_cast<const DWReplayLoginConfigPrefix *>(nativeConfig)->authAddress;
}

extern "C" uint16_t DW_LocalBackend_GetAuthPort(const void *nativeConfig)
{
    return DW_LocalBackend_IsEnabled()
               ? 8443
               : static_cast<const DWReplayLoginConfigPrefix *>(nativeConfig)->authPort;
}

extern "C" const char *DW_LocalBackend_GetLSGAddress(const void *nativeConfig)
{
    return DW_LocalBackend_IsEnabled()
               ? DW_LocalConfig_Host()
               : static_cast<const DWReplayLoginConfigPrefix *>(nativeConfig)->lobbyAddress;
}

extern "C" uint16_t DW_LocalBackend_GetLSGPort(const void *nativeConfig)
{
    return DW_LocalBackend_IsEnabled()
               ? 3075
               : static_cast<const DWReplayLoginConfigPrefix *>(nativeConfig)->lobbyPort;
}

extern "C" void DW_LocalBackend_Status_f()
{
    const unsigned state = __atomic_load_n(&s_probe, __ATOMIC_ACQUIRE);
    Com_Printf(
        25,
        "[DW LOCAL] external transport=%s; auth/tickets/tasks/profiles/matchmaking pending\n",
        state == 2   ? "ready"
        : state == 1 ? "probing"
                     : "unavailable");
    if (state == 2)
        Com_Printf(25, "[DW LOCAL] %s\n", s_response);
}

extern "C" void DW_LocalBackend_Probe_f()
{
    if (!DW_LocalBackend_IsEnabled())
        return;
    unsigned state = __atomic_load_n(&s_probe, __ATOMIC_ACQUIRE);
    if (state == 1 || !__atomic_compare_exchange_n(
                          &s_probe, &state, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    void *thread = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
    if (thread)
        CloseHandle(thread);
    else
    {
        WriteLog("DW_LOCAL_PROBE_FAILED could not create probe thread");
        __atomic_store_n(&s_probe, 3U, __ATOMIC_RELEASE);
    }
}

extern "C" void DW_LocalBackend_Frame()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
        return;
    // Executable-enforced for every DW client, including after namespace or
    // game-mode resets. Resolve the registered native dvar rather than caching
    // a pointer across any deregistration/re-registration boundary.
    if (auto* tutorial = Dvar_FindVarByName("LSPSKLPNQT")) {
        if (tutorial->type == 0 && !tutorial->current.enabled) {
            DvarValue value{};
            value.enabled = true;
            Dvar_SetVariant(tutorial, &value, 0);
        }
    }
    // online_tournament_enabled: the MP play menu builds its tournament entry
    // only while this is set; DW has no tournaments and needs the menu row.
    if (auto* tournament = Dvar_FindVarByName("NLPONNQNRS")) {
        if (tournament->type == 0 && tournament->current.enabled) {
            DvarValue value{};
            Dvar_SetVariant(tournament, &value, 0);
        }
    }
    DW_LocalProgression_Frame();
    DW_WeaponInspectInput_Frame();
    DW_CustomOperators_Frame();
    DW_SlideView_Init();
    DW_ExecutableUpdate_Frame();
    DW_LobbyControls_Frame();
    if (!s_registered)
    {
        // DW runs before Com_DebugStates_Frame. Initialize its default once;
        // subsequent com_debugStates commands can still enable the overlay.
        s_comDebugStates.enabled = 0;
        Cmd_AddCommandInternal("dw_localBackendStatus", DW_LocalBackend_Status_f, &s_statusCommand);
        Cmd_AddCommandInternal("dw_localBackendProbe", DW_LocalBackend_Probe_f, &s_probeCommand);
        WriteEndpointLog("DW_LOCAL_BUILD_INIT host=",
                         "; remote HTTPS=8443 loopback HTTP=8085 lobby=3075; "
                         "workstation-compiled source active");
        s_registered = true;
        DW_LocalBackend_Probe_f();
    }
    const unsigned state = __atomic_load_n(&s_probe, __ATOMIC_ACQUIRE);
    if (state != 1 && state != s_reported)
    {
        s_reported = state;
        DW_LocalBackend_Status_f();
    }
}

// One line appended to replay-dw-client.log (zone and map diagnostics).
extern "C" void DW_LocalBackend_LogLine(const char *message)
{
    WriteLog(message);
}
