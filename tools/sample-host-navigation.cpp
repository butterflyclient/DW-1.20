// Read-only query diagnostics. No VA clones, injection, or game memory writes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processsnapshot.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv)
{
    if (argc != 6 && argc != 7) return 2;
    const DWORD pid = std::strtoul(argv[1], nullptr, 10);
    const DWORD selected = std::strtoul(argv[2], nullptr, 10);
    const unsigned samples = std::strtoul(argv[3], nullptr, 10);
    const auto begin = std::strtoull(argv[4], nullptr, 16);
    const auto end = std::strtoull(argv[5], nullptr, 16);
    const bool compiledWalker = argc == 7 && std::strcmp(argv[6], "rdi") == 0;
    if (!pid || !selected || !samples || samples > 1000 || end <= begin) return 2;
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) return 1;
    auto read = [&](unsigned long long at, void *data, SIZE_T size)
    {
        SIZE_T received = 0;
        return ReadProcessMemory(process, reinterpret_cast<const void *>(at), data, size, &received)
            && received == size;
    };
    unsigned hits = 0;
    for (unsigned sample = 0; sample < samples; ++sample)
    {
        HPSS snapshot = nullptr;
        DWORD error = PssCaptureSnapshot(process, PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
                                         CONTEXT_FULL, &snapshot);
        if (error) { CloseHandle(process); return 1; }
        HPSSWALK marker = nullptr;
        if (!PssWalkMarkerCreate(nullptr, &marker))
        {
            PSS_THREAD_ENTRY thread{};
            while (!PssWalkSnapshot(snapshot, PSS_WALK_THREADS, marker, &thread, sizeof(thread)))
            {
                if (thread.ThreadId != selected || !thread.ContextRecord) continue;
                const auto &context = *thread.ContextRecord;
                if (context.Rip < begin || context.Rip >= end) break;
                unsigned char walker[72]{}, collector[64]{};
                unsigned long long collectorAt = 0, specification = 0, resource = 0;
                float position[3]{}, maximum = 0;
                unsigned filters[5]{};
                // Caller selects a register only after checking the exact
                // image's disassembly and a range after its prologue.
                if (!read(compiledWalker ? context.Rdi : context.Rbx, walker, sizeof(walker))) break;
                std::memcpy(&collectorAt, walker + 32, 8);
                std::memcpy(position, walker + 12, 12);
                if (!collectorAt || !read(collectorAt, collector, sizeof(collector))) break;
                std::memcpy(&specification, collector, 8);
                std::memcpy(&maximum, collector + 8, 4);
                std::memcpy(&resource, collector + 56, 8);
                if (!specification || !read(specification, filters, sizeof(filters))) break;
                std::printf("query,%u,%llx,%g,%g,%g,%g,%x,%x,%x,%x,%x,%llx\n", sample,
                    context.Rip, maximum, position[0], position[1], position[2],
                    filters[0], filters[1], filters[2], filters[3], filters[4], resource);
                ++hits;
                break;
            }
            PssWalkMarkerFree(marker);
        }
        PssFreeSnapshot(GetCurrentProcess(), snapshot);
        Sleep(20);
    }
    std::printf("complete,%u,%u\n", samples, hits);
    CloseHandle(process);
    return 0;
}
