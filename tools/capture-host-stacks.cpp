// Read-only diagnostics for an already-running test. PSS supplies contexts;
// this tool never attaches a debugger, injects code, or writes process memory.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <processsnapshot.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <filesystem>
#include <cstring>

// Copy stack bytes before symbol setup so unwinding never follows a later
// frame's stack contents. All process access remains query/read only.
static DWORD64 s_stackAddress;
static SIZE_T s_stackBytes;
static const unsigned char *s_stack;
static BOOL CALLBACK ReadCapturedStack(HANDLE process, DWORD64 address, void *output,
                                       DWORD bytes, DWORD *received)
{
    if (address >= s_stackAddress && address - s_stackAddress < s_stackBytes)
    {
        if (bytes > s_stackBytes - (address - s_stackAddress))
            return FALSE;
        std::memcpy(output, s_stack + (address - s_stackAddress), bytes);
        *received = bytes;
        return TRUE;
    }
    SIZE_T copied = 0;
    const BOOL result = ReadProcessMemory(process, reinterpret_cast<const void *>(address),
                                         output, bytes, &copied);
    *received = static_cast<DWORD>(copied);
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4)
        return 2;
    const DWORD pid = std::strtoul(argv[1], nullptr, 10);
    const std::filesystem::path directory(argv[2]);
    std::filesystem::create_directories(directory);
    if (argc == 4 && std::strncmp(argv[3], "clone:", 6) == 0)
    {
        std::fprintf(stderr, "VA cloning is disabled; use lightweight thread contexts.\n");
        return 2;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process)
        return 1;
    const DWORD selectedThread = argc == 4 && std::strncmp(argv[3], "thread:", 7) == 0
        ? std::strtoul(argv[3] + 7, nullptr, 10) : 0;
    if (argc == 4 && !selectedThread)
    {
        // Optional exception CONTEXT address found in a previous stack capture.
        CONTEXT context{};
        SIZE_T received = 0;
        const auto address = std::strtoull(argv[3], nullptr, 16);
        if (!ReadProcessMemory(process, reinterpret_cast<const void *>(address),
                               &context, sizeof(context), &received) || received != sizeof(context))
            return 1;
        std::printf("context,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
            context.Rip, context.Rsp, context.Rcx, context.Rdx, context.R8,
            context.R9, context.R14, context.R15);
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS);
        if (!SymInitialize(process, "", TRUE))
            return 1;
        STACKFRAME64 frame{};
        frame.AddrPC = {context.Rip, 0, AddrModeFlat};
        frame.AddrFrame = {context.Rbp, 0, AddrModeFlat};
        frame.AddrStack = {context.Rsp, 0, AddrModeFlat};
        for (unsigned i = 0; i < 64; ++i)
        {
            std::printf("frame,%u,%llx,%llx\n", i, frame.AddrPC.Offset, frame.AddrStack.Offset);
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, nullptr, &frame,
                            &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
                break;
        }
        SymCleanup(process);
        CloseHandle(process);
        return 0;
    }
    HPSS snapshot = nullptr;
    DWORD error = PssCaptureSnapshot(process,
        PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT, CONTEXT_FULL, &snapshot);
    if (error)
    {
        std::fprintf(stderr, "PssCaptureSnapshot: %lu\n", error);
        CloseHandle(process);
        return 1;
    }
    HPSSWALK marker = nullptr;
    HANDLE memory = process;
    error = PssWalkMarkerCreate(nullptr, &marker);
    if (!error)
    {
        PSS_THREAD_ENTRY thread{};
        while ((error = PssWalkSnapshot(snapshot, PSS_WALK_THREADS, marker,
                                       &thread, sizeof(thread))) == ERROR_SUCCESS)
        {
            if (!thread.ContextRecord || (thread.Flags & PSS_THREAD_FLAGS_TERMINATED))
                continue;
            if (selectedThread && selectedThread != thread.ThreadId)
                continue;
            const auto &context = *thread.ContextRecord;
            unsigned long long tib[3]{};
            SIZE_T received = 0;
            const bool haveTib = ReadProcessMemory(memory, thread.TebBaseAddress,
                tib, sizeof(tib), &received) && received == sizeof(tib);
            SIZE_T bytes = haveTib && tib[1] > context.Rsp ? tib[1] - context.Rsp : 65536;
            if (bytes > 65536)
                bytes = 65536;
            std::vector<unsigned char> stack(bytes);
            ReadProcessMemory(memory, reinterpret_cast<const void *>(context.Rsp),
                              stack.data(), stack.size(), &received);
            if (selectedThread)
            {
                CONTEXT captured = *thread.ContextRecord;
                s_stackAddress = context.Rsp;
                s_stackBytes = received;
                s_stack = stack.data();
                SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS);
                if (SymInitialize(memory, "", TRUE))
                {
                    STACKFRAME64 frame{};
                    frame.AddrPC = {captured.Rip, 0, AddrModeFlat};
                    frame.AddrFrame = {captured.Rbp, 0, AddrModeFlat};
                    frame.AddrStack = {captured.Rsp, 0, AddrModeFlat};
                    for (unsigned i = 0; i < 64; ++i)
                    {
                        std::printf("frame,%u,%llx,%llx\n", i,
                            frame.AddrPC.Offset, frame.AddrStack.Offset);
                        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, memory, nullptr,
                            &frame, &captured, ReadCapturedStack, SymFunctionTableAccess64,
                            SymGetModuleBase64, nullptr))
                            break;
                    }
                    SymCleanup(memory);
                }
            }
            PWSTR description = nullptr;
            HANDLE handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread.ThreadId);
            if (handle)
            {
                GetThreadDescription(handle, &description);
                CloseHandle(handle);
            }
            if (received)
            {
                const auto path = directory / (std::to_string(thread.ThreadId) + ".stack");
                FILE *file = nullptr;
                if (!fopen_s(&file, path.string().c_str(), "wb"))
                {
                    std::fwrite(stack.data(), 1, received, file);
                    std::fclose(file);
                }
            }
            std::printf("%lu,%llx,%llx,%llx,%llx,%llu,%ls\n", thread.ThreadId,
                context.Rip, context.Rsp, context.R14, context.R15,
                static_cast<unsigned long long>(received), description ? description : L"");
            LocalFree(description);
        }
        PssWalkMarkerFree(marker);
    }
    PssFreeSnapshot(GetCurrentProcess(), snapshot);
    CloseHandle(process);
    return error == ERROR_NO_MORE_ITEMS ? 0 : 1;
}
