// Process-local diagnostic sampling; no code injection, settings or memory writes.
// Windows owns capture/release of thread contexts. Captures include waiting
// threads, so consumers must keep thread CPU deltas separate from sample counts.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <processsnapshot.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>

static unsigned long long Ticks(FILETIME time)
{
    return (static_cast<unsigned long long>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

int main(int argc, char** argv)
{
    if (argc != 3) return 2;
    const auto pid = static_cast<DWORD>(std::strtoul(argv[1], nullptr, 10));
    const unsigned count = static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10));
    if (!pid || !count || count > 1000) return 2;
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) { std::fprintf(stderr, "OpenProcess: %lu\n", GetLastError()); return 1; }
    HMODULE modules[1024];
    DWORD bytes = 0;
    if (EnumProcessModulesEx(process, modules, sizeof(modules), &bytes, LIST_MODULES_ALL))
        for (unsigned i = 0; i < bytes / sizeof(HMODULE) && i < 1024; ++i)
        {
            MODULEINFO info{};
            char name[MAX_PATH]{};
            if (GetModuleInformation(process, modules[i], &info, sizeof(info)) &&
                GetModuleFileNameExA(process, modules[i], name, sizeof(name)))
                std::printf("module,%llx,%lu,%s\n",
                    reinterpret_cast<unsigned long long>(info.lpBaseOfDll), info.SizeOfImage, name);
        }
    const auto start = GetTickCount64();
    int result = 0;
    for (unsigned sample = 0; sample < count; ++sample)
    {
        HPSS snapshot = nullptr;
        const auto begin = GetTickCount64();
        DWORD error = PssCaptureSnapshot(process, PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
                                        CONTEXT_CONTROL, &snapshot);
        if (error) { std::fprintf(stderr, "PssCaptureSnapshot: %lu\n", error); result = 1; break; }
        HPSSWALK marker = nullptr;
        error = PssWalkMarkerCreate(nullptr, &marker);
        if (!error)
        {
            PSS_THREAD_ENTRY thread{};
            while ((error = PssWalkSnapshot(snapshot, PSS_WALK_THREADS, marker,
                                            &thread, sizeof(thread))) == ERROR_SUCCESS)
                if (thread.ContextRecord && !(thread.Flags & PSS_THREAD_FLAGS_TERMINATED))
                    std::printf("sample,%u,%llu,%lu,%llx,%llu,%llu\n", sample,
                        begin - start, thread.ThreadId, thread.ContextRecord->Rip,
                        Ticks(thread.UserTime), Ticks(thread.KernelTime));
            PssWalkMarkerFree(marker);
        }
        PssFreeSnapshot(GetCurrentProcess(), snapshot);
        if (error != ERROR_NO_MORE_ITEMS)
        {
            std::fprintf(stderr, "PssWalkSnapshot: %lu\n", error); result = 1; break;
        }
        std::printf("capture,%u,%llu\n", sample, GetTickCount64() - begin);
        Sleep(20);
    }
    CloseHandle(process);
    return result;
}
