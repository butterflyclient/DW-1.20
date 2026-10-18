"""Compile source-only request diagnostics and exercise transport/lifetime boundaries.

No game process is opened. The only network test contacts a closed loopback port.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
CLANG = Path(r"C:\Program Files\LLVM\bin\clang++.exe")
LINK = CLANG.with_name("lld-link.exe")

COMMON = r"""

#include "DW_NetworkDiagnostics.h"
#include <stddef.h>
namespace DWNetworkDiagnostics::Detail
{
    Slot slots[SlotCount]{};
    uintptr_t nextId = 0;
} // namespace DWNetworkDiagnostics::Detail
static unsigned logCount = 0;
static char lines[20000][352]{};
static uint64_t ticks = 0;
static uint64_t GetTickCount64()
{
    return __atomic_add_fetch(&ticks, 1, __ATOMIC_RELAXED);
}
static void Log(const char *text)
{
    const unsigned row = __atomic_fetch_add(&logCount, 1, __ATOMIC_RELAXED);
    if (row >= 20000)
        return;
    unsigned column = 0;
    while (*text && column < 351)
        lines[row][column++] = *text++;
    lines[row][column] = 0;
}
extern "C" void *memset(void *p, int value, size_t size)
{
    auto bytes = static_cast<unsigned char *>(p);
    while (size--)
        *bytes++ = static_cast<unsigned char>(value);
    return p;
}
extern "C" __declspec(dllexport) void Clear()
{
    logCount = 0;
}
extern "C" __declspec(dllexport) unsigned Count()
{
    return logCount;
}
extern "C" __declspec(dllexport) const char *Line(unsigned index)
{
    return lines[index];
}
extern "C" __declspec(dllexport) uintptr_t CounterAddress()
{
    return reinterpret_cast<uintptr_t>(&DWNetworkDiagnostics::Detail::nextId);
}
"""

TRANSPORT = r"""

static unsigned scenario = 0, reads = 0;
static bool healthMode = false;
static unsigned healthOffset = 0;
static bool Equal(const char *left, const char *right)
{
    while (*left && *left == *right)
    {
        ++left;
        ++right;
    }
    return *left == *right;
}
static unsigned long GetCurrentProcessId()
{
    return 4242;
}
static unsigned long GetLastError()
{
    return 12002;
}
static void *LoadLibraryA(const char *)
{
    return scenario == 18 ? nullptr : reinterpret_cast<void *>(1);
}
static int FreeLibrary(void *)
{
    return 1;
}
static bool DW_LocalConfig_UseTls()
{
    return true;
}
static const char *DW_LocalConfig_Host()
{
    return "162.243.115.160";
}
static const wchar_t *DW_LocalConfig_WideHost()
{
    return L"162.243.115.160";
}
static const wchar_t *DW_LocalConfig_Headers()
{
    return L"Content-Type: application/octet-stream\r\n";
}
static void *Open(const wchar_t *, unsigned long, const wchar_t *, const wchar_t *, unsigned long)
{
    return scenario == 1 ? nullptr : reinterpret_cast<void *>(1);
}
static int Timeouts(void *, int, int, int, int)
{
    return scenario != 2;
}
static void *Connect(void *, const wchar_t *, unsigned short, unsigned long)
{
    return scenario == 3 ? nullptr : reinterpret_cast<void *>(2);
}
static void *OpenRequest(void *, const wchar_t *, const wchar_t *, const wchar_t *, const wchar_t *,
                         const wchar_t **, unsigned long)
{
    return scenario == 4 ? nullptr : reinterpret_cast<void *>(3);
}
static int Option(void *, unsigned long option, void *, unsigned long)
{
    return (option != 88 || scenario != 5) && (option != 45 || scenario != 20);
}
static DWNetworkDiagnostics::Callback SetCallback(void *, DWNetworkDiagnostics::Callback,
                                                  unsigned long, uintptr_t)
{
    return scenario == 14 ? reinterpret_cast<DWNetworkDiagnostics::Callback>(~uintptr_t{0})
                          : nullptr;
}
static int Send(void *, const wchar_t *, unsigned long, void *, unsigned long, unsigned long,
                uintptr_t context)
{
    DWNetworkDiagnostics::Detail::Status(nullptr, context, 0x4, nullptr, 0);
    DWNetworkDiagnostics::Detail::Status(nullptr, context, 0x8, nullptr, 0);
    return scenario != 6;
}
static int Receive(void *, void *)
{
    return scenario != 7;
}
static int Headers(void *, unsigned long, const wchar_t *, void *status, unsigned long *,
                   unsigned long *)
{
    *static_cast<unsigned long *>(status) = scenario == 9 ? 503 : 200;
    return scenario != 8;
}
static int Read(void *, void *output, unsigned long capacity, unsigned long *received)
{
    ++reads;
    if ((scenario == 10 && reads == 1) || (scenario == 12 && reads == 2))
        return 0;
    if (healthMode)
    {
        const char valid[] = "{\"server\":\"iw8-dw\",\"build\":\"replay120\",\"stage\":\"transport-ready\"}";
        const char invalid[] = "{\"server\":\"wrong-server\"}";
        const char *payload = scenario == 15 ? invalid : valid;
        unsigned length = 0;
        while (payload[length])
            ++length;
        const unsigned total = scenario == 13 ? 2047 : (scenario == 11 ? 0 : length);
        unsigned count = total - healthOffset;
        if (count > capacity)
            count = capacity;
        if (scenario == 16 && count > 7)
            count = 7;
        for (unsigned i = 0; i < count; ++i)
            static_cast<char *>(output)[i] = healthOffset + i < length ? payload[healthOffset + i] : ' ';
        healthOffset += count;
        *received = count;
        return 1;
    }
    *received = reads == 1 ? (scenario == 11 ? 0 : capacity) : (scenario == 13 ? 1 : 0);
    if (*received)
        *static_cast<char *>(output) = 0;
    return 1;
}
static int Close(void *)
{
    return 1;
}
static void *GetProcAddress(void *, const char *name)
{
    if (scenario == 19 && Equal(name, "WinHttpReadData"))
        return nullptr;
#define MATCH(api, function)                                                                       \
    if (Equal(name, api))                                                                          \
        return reinterpret_cast<void *>(&function);
    MATCH("WinHttpOpen", Open)
    MATCH("WinHttpConnect", Connect)
    MATCH("WinHttpOpenRequest", OpenRequest)
    MATCH("WinHttpSetTimeouts", Timeouts)
    MATCH("WinHttpSetOption", Option)
    MATCH("WinHttpSetStatusCallback", SetCallback)
    MATCH("WinHttpSendRequest", Send)
    MATCH("WinHttpReceiveResponse", Receive)
    MATCH("WinHttpQueryHeaders", Headers)
    MATCH("WinHttpReadData", Read)
    MATCH("WinHttpCloseHandle", Close)
#undef MATCH
    return nullptr;
}
"""

HARNESS = r"""

extern "C" __declspec(dllexport) int RunPost(unsigned value)
{
    scenario = value;
    healthMode = false;
    reads = 0;
    char body[104]{}, output[32]{};
    return DW_LocalPlatform_Post(L"/platform/client/challenge", body, 104, output, 32);
}
using DiagnosticRequest = DWNetworkDiagnostics::Request;
alignas(DiagnosticRequest) static unsigned char requests[32][sizeof(DiagnosticRequest)];
inline void *operator new(size_t, void *location)
{
    return location;
}
static DiagnosticRequest *At(unsigned slot)
{
    return reinterpret_cast<DiagnosticRequest *>(requests[slot]);
}
static int TraceOption(void *, unsigned long, void *, unsigned long)
{
    return 1;
}
static DWNetworkDiagnostics::Callback TraceCallback(void *, DWNetworkDiagnostics::Callback,
                                                   unsigned long, uintptr_t)
{
    return nullptr;
}
extern "C" __declspec(dllexport) uintptr_t Start(unsigned slot)
{
    auto request = new (requests[slot]) DiagnosticRequest(
        DWNetworkDiagnostics::Operation::Health, "162.243.115.160", 8443, Log, GetTickCount64);
    request->Attach(reinterpret_cast<void *>(4), TraceOption, TraceCallback);
    return request->Context();
}
extern "C" __declspec(dllexport) uintptr_t StartNative(unsigned slot)
{
    auto request = new (requests[slot]) DiagnosticRequest(DWNetworkDiagnostics::Operation::Health,
                                                          "127.0.0.1", 1, Log, GetTickCount64);
    request->Attach(reinterpret_cast<void *>(4), TraceOption, TraceCallback);
    return request->Context();
}
extern "C" __declspec(dllexport) void Emit(uintptr_t id, unsigned long status)
{
    uint32_t flags = 8;
    DWNetworkDiagnostics::Detail::Status(nullptr, id, status, &flags, sizeof(flags));
}
extern "C" __declspec(dllexport) void Finish(unsigned slot)
{
    At(slot)->Complete(true, 0, 200, 32, 32, 0);
    At(slot)->~DiagnosticRequest();
}
extern "C" __declspec(dllexport) void NativeAttach(unsigned slot, void *handle,
                                                   DWNetworkDiagnostics::SetOption option,
                                                   DWNetworkDiagnostics::SetCallback callback)
{
    At(slot)->Detach();
    At(slot)->Attach(handle, option, callback);
}
extern "C" __declspec(dllexport) void NativeFinish(unsigned slot, unsigned long error)
{
    At(slot)->Begin(DWNetworkDiagnostics::Stage::Send);
    At(slot)->Complete(false, error, 0, 0, 32, 0);
    At(slot)->~DiagnosticRequest();
}
extern "C" __declspec(dllexport) unsigned Label(const wchar_t *path)
{
    return static_cast<unsigned>(DWNetworkDiagnostics::OperationForPath(path));
}
"""

# Frozen R19 source, commit 91acd15; function renamed only for differential testing.
LEGACY_PROBE = r"""
    unsigned long __stdcall LegacyProbeThread(void *)
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
        void *library = LoadLibraryA("winhttp.dll");
        bool ok = false;
        s_response[0] = 0;
        if (library)
        {
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
            const bool tls = DW_LocalConfig_UseTls();
            unsigned long redirectPolicy = 0; // WINHTTP_OPTION_REDIRECT_POLICY_NEVER
            if (open && connect && request && timeouts && send && receive && headers && read &&
                close)
            {
                Handle session = open(L"IW8-Replay-LocalDW/1", 1, nullptr, nullptr, 0);
                Handle connection = nullptr, message = nullptr;
                if (session && timeouts(session, 1000, 1000, 1000, 1000))
                    connection = connect(session, DW_LocalConfig_WideHost(), tls ? 8443 : 8085, 0);
                if (connection)
                    message = request(connection, L"GET", L"/health", nullptr, nullptr, nullptr, tls ? 0x00800000 : 0);
                if (message && option && option(message, 88, &redirectPolicy, sizeof(redirectPolicy)) && send(message, nullptr, 0, nullptr, 0, 0, 0) &&
                    receive(message, nullptr))
                {
                    unsigned long status = 0, statusSize = sizeof(status);
                    if (headers(message, 0x20000013, nullptr, &status, &statusSize, nullptr) &&
                        status == 200)
                    {
                        unsigned used = 0;
                        bool complete = false;
                        while (used < sizeof(s_response) - 1)
                        {
                            unsigned long received = 0;
                            if (!read(message,
                                      s_response + used,
                                      static_cast<unsigned long>(sizeof(s_response) - 1 - used),
                                      &received))
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
                    }
                }
                if (message)
                    close(message);
                if (connection)
                    close(connection);
                if (session)
                    close(session);
            }
            FreeLibrary(library);
        }
        WriteEndpointLog(ok ? "DW_LOCAL_PROBE_OK host=" : "DW_LOCAL_PROBE_FAILED host=",
                         ok ? " backend health reached; native authentication/tasks pending"
                            : " backend health unavailable; check this endpoint's server "
                              "and network access");
        __atomic_store_n(&s_probe, ok ? 2U : 3U, __ATOMIC_RELEASE);
        return 0;
    }
"""


def compile_library(directory, inputs):
    source = inputs["platform"].read_text()
    begin = source.index('extern "C" bool DW_LocalPlatform_Post(')
    end = source.index("\nnamespace", begin)
    main = directory / "diagnostics.cpp"
    frame = inputs["frame"].read_text()
    health_begin = frame.index("    unsigned long __stdcall ProbeThread(void *)")
    health_end = frame.index("\n} // namespace", health_begin)
    health_support = r"""
static unsigned s_probe = 0;
static char s_response[2048]{};
static void WriteLog(const char *text)
{
    Log(text);
}
static void WriteEndpointLog(const char *prefix, const char *)
{
    Log(prefix);
}
static bool Contains(const char *text, const char *needle)
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
"""
    health_export = r"""
extern "C" __declspec(dllexport) unsigned RunHealth(unsigned value, bool legacy)
{
    scenario = value;
    reads = healthOffset = s_probe = 0;
    healthMode = true;
    if (legacy)
        LegacyProbeThread(nullptr);
    else
        ProbeThread(nullptr);
    return s_probe;
}
"""
    main.write_text(
        COMMON
        + TRANSPORT
        + source[begin:end]
        + HARNESS
        + health_support
        + LEGACY_PROBE
        + frame[health_begin:health_end]
        + health_export
    )
    other = directory / "other.cpp"
    other.write_text(
        '#include "DW_NetworkDiagnostics.h"\n'
        'extern "C" __declspec(dllexport) uintptr_t OtherCounterAddress()\n'
        "{ return reinterpret_cast<uintptr_t>(&DWNetworkDiagnostics::Detail::nextId); }\n"
    )
    objects = []
    for path in (main, other):
        obj = path.with_suffix(".obj")
        subprocess.run(
            [
                str(CLANG),
                "--target=x86_64-pc-windows-msvc",
                "-c",
                str(path),
                "-o",
                str(obj),
                "-O2",
                "-std=c++20",
                "-ffreestanding",
                "-fno-stack-protector",
                "-fno-exceptions",
                "-fno-rtti",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I" + str(inputs["header"].parent),
            ],
            check=True,
        )
        objects.append(str(obj))
    dll = directory / "diagnostics.dll"
    subprocess.run(
        [str(LINK), "/dll", "/noentry", "/nodefaultlib", *objects, "/out:" + str(dll)],
        check=True,
    )
    return ctypes.CDLL(str(dll))


def messages(library):
    return [library.Line(i).decode("ascii") for i in range(library.Count())]


def configure(library):
    library.RunHealth.argtypes = [ctypes.c_uint, ctypes.c_bool]
    library.RunHealth.restype = ctypes.c_uint
    library.Line.argtypes = [ctypes.c_uint]
    library.Line.restype = ctypes.c_char_p
    for name in ("CounterAddress", "OtherCounterAddress"):
        getattr(library, name).restype = ctypes.c_size_t
    library.Start.argtypes = [ctypes.c_uint]
    library.Start.restype = ctypes.c_size_t
    library.StartNative.argtypes = [ctypes.c_uint]
    library.StartNative.restype = ctypes.c_size_t
    library.Emit.argtypes = [ctypes.c_size_t, wintypes.DWORD]
    library.Finish.argtypes = [ctypes.c_uint]
    library.Label.argtypes = [ctypes.c_wchar_p]
    library.NativeAttach.argtypes = [
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.NativeFinish.argtypes = [ctypes.c_uint, wintypes.DWORD]


def transport_cases(library):
    stages = [
        "complete",
        "open",
        "timeouts",
        "connect",
        "open-request",
        "redirect-policy",
        "send",
        "receive",
        "query-status",
        "http-status",
        "read",
        "short-response",
        "read-eof",
        "long-response",
        "complete",
    ]
    rows = []
    for index, stage in enumerate(stages):
        library.Clear()
        accepted = bool(library.RunPost(index))
        lines = messages(library)
        summary = next(line for line in lines if line.startswith("DW_NETWORK end"))
        assert accepted == (index in (0, 14)), (index, summary)
        assert "stage=" + stage + " " in summary, (index, summary)
        assert "process=4242 " in summary
        assert all(len(line) < 352 for line in lines)
        assert all(
            "/platform" not in line and "octet-stream" not in line for line in lines
        )
        assert len(lines) <= 26
        rows.append(dict(scenario=index, accepted=accepted, summary=summary))
    assert library.Label("/platform/client/challenge") == 1
    assert library.Label("/platform/client/login") == 2
    assert library.Label("/platform/client/renew") == 3
    assert library.Label("/platform/client/login?secret=must-not-log") == 4
    return rows


def health_cases(library):
    rows = []
    scenarios = list(range(17)) + [18, 19, 20]
    for scenario in scenarios:
        library.Clear()
        original = library.RunHealth(scenario, True)
        library.Clear()
        edited = library.RunHealth(scenario, False)
        lines = messages(library)
        summary = next(line for line in lines if line.startswith("DW_NETWORK end"))
        assert edited == original, (scenario, original, edited, summary)
        assert edited == (2 if scenario in (0, 14, 16, 20) else 3)
        assert len(lines) <= 27
        assert all(len(line) < 352 for line in lines)
        if scenario in (11, 13, 15):
            assert "stage=validate-body " in summary and "win32=0 " in summary
        if scenario == 13:
            assert "received=2047 " in summary
        rows.append(
            dict(
                scenario=scenario,
                legacy_probe_state=original,
                diagnostic_probe_state=edited,
                summary=summary,
            )
        )
    return rows


def lifetime_cases(library):
    assert library.CounterAddress() == library.OtherCounterAddress()
    library.Clear()
    old = library.Start(0)
    library.Emit(old, 0x10000)
    library.Finish(0)
    assert any("secure_flags=8" in line for line in messages(library))
    library.Clear()
    # Retire and reuse every registry bucket. Old integer contexts remain harmless.
    for _ in range(32):
        current = library.Start(0)
        library.Emit(old, 0x10000)
        library.Finish(0)
    assert not any("tls-failure" in line for line in messages(library))
    library.Clear()
    active = library.Start(0)
    started = threading.Event()

    def racing_callback():
        for _ in range(10000):
            library.Emit(active, 0x10000)
            started.set()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(racing_callback)
        assert started.wait(5)
        library.Finish(0)
        library.Clear()
        for _ in range(32):
            library.Start(0)
            library.Finish(0)
        future.result()
    assert not any("tls-failure" in line for line in messages(library))
    library.Clear()

    def worker(slot):
        for _ in range(80):
            identity = library.Start(slot)
            library.Emit(identity, 0x4)
            library.Emit(identity, 0x8)
            library.Finish(slot)
            library.Emit(identity, 0x10000)

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(worker, range(16)))
    lines = messages(library)
    begins = [
        line.split("request=", 1)[1].split()[0]
        for line in lines
        if line.startswith("DW_NETWORK begin")
    ]
    assert len(begins) == 1280 and len(set(begins)) == 1280
    assert not any("tls-failure" in line for line in lines)
    return dict(
        two_translation_units_share_counter=True,
        late_callback_reuse_rejected=True,
        callback_teardown_race_iterations=10000,
        concurrent_threads=16,
        concurrent_requests=1280,
        unique_request_ids=len(set(begins)),
    )


def native_failure_case(library):
    http = ctypes.WinDLL("winhttp", use_last_error=True)
    pointer = ctypes.c_void_p
    dword = wintypes.DWORD
    signatures = {
        "WinHttpOpen": (
            [ctypes.c_wchar_p, dword, ctypes.c_wchar_p, ctypes.c_wchar_p, dword],
            pointer,
        ),
        "WinHttpSetTimeouts": (
            [pointer, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int],
            wintypes.BOOL,
        ),
        "WinHttpConnect": ([pointer, ctypes.c_wchar_p, wintypes.WORD, dword], pointer),
        "WinHttpOpenRequest": (
            [
                pointer,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                pointer,
                pointer,
                pointer,
                dword,
            ],
            pointer,
        ),
        "WinHttpSendRequest": (
            [pointer, pointer, dword, pointer, dword, dword, ctypes.c_size_t],
            wintypes.BOOL,
        ),
        "WinHttpCloseHandle": ([pointer], wintypes.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(http, name)
        function.argtypes = arguments
        function.restype = result
    library.Clear()
    identity = library.StartNative(0)
    handles = []
    try:
        session = http.WinHttpOpen("IW8-Diagnostic-Test/1", 1, None, None, 0)
        assert session
        handles.append(session)
        assert http.WinHttpSetTimeouts(session, 1000, 1000, 1000, 1000)
        connection = http.WinHttpConnect(session, "127.0.0.1", 1, 0)
        assert connection
        handles.append(connection)
        request = http.WinHttpOpenRequest(
            connection, "GET", "/health", None, None, None, 0
        )
        assert request
        handles.append(request)
        library.NativeAttach(
            0,
            request,
            ctypes.cast(http.WinHttpSetOption, pointer),
            ctypes.cast(http.WinHttpSetStatusCallback, pointer),
        )
        ctypes.set_last_error(0)
        sent = http.WinHttpSendRequest(request, None, 0, None, 0, 0, identity)
        error = ctypes.get_last_error()
        assert not sent and error != 0, "Loopback port 1 must be closed for this test"
        library.NativeFinish(0, error)
    finally:
        for handle in reversed(handles):
            http.WinHttpCloseHandle(handle)
    lines = messages(library)
    summary = next(line for line in lines if line.startswith("DW_NETWORK end"))
    assert f"win32={error} " in summary and "callback=1" in summary
    assert any("event=connect-start" in line for line in lines)
    return dict(
        passed=True, endpoint="http://127.0.0.1:1/health", win32=error, log=lines
    )


def source_inputs(build):
    if build is None:
        directory = ROOT / "integration/replay"
        return (
            dict(
                platform=directory / "DW_LocalPlatform.cpp",
                frame=directory / "DW_LocalBackend_Frame.cpp",
                header=directory / "DW_NetworkDiagnostics.h",
            ),
            None,
        )
    report_path = build / "build-report.json"
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    snapshot = Path(report["source_root"]).resolve()
    receipt_path = snapshot.parent / "source-receipt.json"
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    assert Path(receipt["snapshot"]).resolve() == snapshot
    inputs = {}
    associations = []
    for label, name in (
        ("platform", "DW_LocalPlatform.cpp"),
        ("frame", "DW_LocalBackend_Frame.cpp"),
        ("header", "DW_NetworkDiagnostics.h"),
    ):
        expected = "integration/replay/" + name
        rows = [
            entry for entry in receipt["source_inputs"] if entry["source"] == expected
        ]
        assert len(rows) == 1, ("Frozen source association missing", expected)
        row = rows[0]
        path = (snapshot / row["compiled_source"]).resolve()
        path.relative_to(snapshot)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == row["compiled_sha256"]
        inputs[label] = path
        if label == "header":
            continue
        units = [
            entry
            for entry in report["cpp"]
            if entry["source"] == row["compiled_source"]
        ]
        assert len(units) == 1, ("Compiled source association missing", expected)
        unit = units[0]
        assert unit["source_sha256"] == digest
        assert (
            hashlib.sha256(Path(unit["object"]).read_bytes()).hexdigest()
            == unit["object_sha256"]
        )
        associations.append(
            dict(
                source=row["compiled_source"],
                sha256=digest,
                object_sha256=unit["object_sha256"],
            )
        )
    header_hash = hashlib.sha256(inputs["header"].read_bytes()).hexdigest()
    for association in associations:
        unit = next(
            entry for entry in report["cpp"] if entry["source"] == association["source"]
        )
        dependencies = [
            entry
            for entry in unit["dependencies"]
            if Path(entry["path"]).resolve() == inputs["header"]
        ]
        assert len(dependencies) == 1 and dependencies[0]["sha256"] == header_hash
    executable = Path(report["executable"])
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == report["sha256"]
    proof = dict(
        build_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
        source_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        linked_executable_sha256=report["sha256"],
        associations=associations,
        header_dependency_sha256=header_hash,
        scope="Recompiled frozen source harness; final executable hash verified but not executed",
    )
    return inputs, proof


def syntax_checks(inputs, build):
    if build:
        includes = (
            Path(json.loads((build / "build-report.json").read_bytes())["source_root"])
            / "src"
        )
    else:
        latest = json.loads((ROOT / "data/dw-client/latest-job.json").read_bytes())
        includes = Path(latest["directory"]) / "source/src"
    for key in ("platform", "frame"):
        subprocess.run(
            [
                str(CLANG),
                "--target=x86_64-pc-windows-msvc",
                "-fsyntax-only",
                "-std=c++20",
                "-ffreestanding",
                "-fno-exceptions",
                "-fno-rtti",
                "-I" + str(inputs["header"].parent),
                "-I" + str(includes),
                str(inputs[key]),
            ],
            check=True,
        )
    return dict(passed=True, translation_units=2, includes=str(includes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    args = parser.parse_args()
    inputs, association = source_inputs(args.build)
    syntax = syntax_checks(inputs, args.build)
    with tempfile.TemporaryDirectory(
        prefix="network-diagnostics-", dir=ROOT / "tools/build"
    ) as temp:
        library = compile_library(Path(temp), inputs)
        try:
            configure(library)
            report = dict(
                passed=True,
                source_only=True,
                final_executable_executed=False,
                linked_executable_sha256=(
                    association["linked_executable_sha256"] if association else None
                ),
                build_source_association=association,
                syntax=syntax,
                legacy_health_commit="91acd15",
                legacy_health_function_sha256=hashlib.sha256(
                    LEGACY_PROBE.encode()
                ).hexdigest(),
                health_source_sha256=hashlib.sha256(
                    inputs["frame"].read_bytes()
                ).hexdigest(),
                game_process_accessed=False,
                post_source_sha256=hashlib.sha256(
                    inputs["platform"].read_bytes()
                ).hexdigest(),
                header_sha256=hashlib.sha256(inputs["header"].read_bytes()).hexdigest(),
                transport=transport_cases(library),
                health=health_cases(library),
                lifetime=lifetime_cases(library),
                native_failure=native_failure_case(library),
            )
        finally:
            kernel = ctypes.WinDLL("kernel32")
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            kernel.FreeLibrary(library._handle)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
