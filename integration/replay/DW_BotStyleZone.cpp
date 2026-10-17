#include "DW_BotStyleScriptPackage.h"
#include "DW_BotStyleZoneBindings.h"
#include "DW_MapImagesPackage.h"
#include "DW_WeaponInspectPackage.h"
#include <stddef.h>
#include <stdint.h>

// Complete generated resource descriptor; names cover both files for every
// native locale dependency without a second local asset inventory.
static_assert(sizeof(DWBotStyleScriptPackage) == 96);
static_assert(offsetof(DWBotStyleScriptPackage, zoneName) == 0);
static_assert(offsetof(DWBotStyleScriptPackage, fastfile) == 8);
static_assert(offsetof(DWBotStyleScriptPackage, fastfileBytes) == 16);
static_assert(offsetof(DWBotStyleScriptPackage, patch) == 24);
static_assert(offsetof(DWBotStyleScriptPackage, patchBytes) == 32);
static_assert(offsetof(DWBotStyleScriptPackage, emptyFastfile) == 40);
static_assert(offsetof(DWBotStyleScriptPackage, emptyFastfileBytes) == 48);
static_assert(offsetof(DWBotStyleScriptPackage, emptyPatch) == 56);
static_assert(offsetof(DWBotStyleScriptPackage, emptyPatchBytes) == 64);
static_assert(offsetof(DWBotStyleScriptPackage, installationNames) == 72);
static_assert(offsetof(DWBotStyleScriptPackage, installationDirectories) == 80);
static_assert(offsetof(DWBotStyleScriptPackage, installationNameCount) == 88);
static_assert(offsetof(DWBotStyleScriptPackage, reserved) == 92);

// Complete Replay 1.20 record consumed by DB_LoadFastfiles. The final word is
// padding, but is retained when copying a native request.
struct DWBotStyleFastfileInfo
{
    const char *name;
    uint32_t zoneFlags;
    uint32_t failureMode;
    uint32_t priority;
    uint32_t reserved;
};
static_assert(sizeof(DWBotStyleFastfileInfo) == 24);
static_assert(offsetof(DWBotStyleFastfileInfo, name) == 0);
static_assert(offsetof(DWBotStyleFastfileInfo, zoneFlags) == 8);
static_assert(offsetof(DWBotStyleFastfileInfo, failureMode) == 12);
static_assert(offsetof(DWBotStyleFastfileInfo, priority) == 16);
static_assert(offsetof(DWBotStyleFastfileInfo, reserved) == 20);

extern "C"
{
    const DWBotStyleScriptPackage *DW_BotStyleScripts_GetPackage();
    bool DW_MapImages_ZoneInstalled(); // DW_MapAvailability.cpp
    void DW_BotStyleZone_LoadFastfilesNative(const DWBotStyleFastfileInfo *, uint32_t, uint32_t,
                                             bool);
    unsigned DWBSZ_PollFastfileState(const char *);
    const char *DWBSZ_CurrentRegionCode();
    const char *DWBSZ_CurrentLanguageCode();
    bool DWBSZ_IsLocalized(const char *);
    bool DWBSZ_IsRegional(const char *);
    void DWBSZ_BuildAbsPath(char *, int, unsigned, const char *, const char *);
    void DWBSZ_Print(int, const char *, ...);
    void DW_LocalBackend_LogLine(const char *); // DW_LocalBackend_Frame.cpp
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
}

namespace
{
using File = void *(__stdcall *)(const wchar_t *, unsigned long, unsigned long, void *,
                                 unsigned long, unsigned long, void *);
using IO = int(__stdcall *)(void *, void *, unsigned long, unsigned long *, void *);
using Name = unsigned long(__stdcall *)(void *, wchar_t *, unsigned long);
using Move = int(__stdcall *)(const wchar_t *, const wchar_t *, unsigned long);
using Delete = int(__stdcall *)(const wchar_t *);
using Flush = int(__stdcall *)(void *);
using Pid = unsigned long(__stdcall *)();
using Heap = void *(__stdcall *)();
using Alloc = void *(__stdcall *)(void *, unsigned long, size_t);
using Free = int(__stdcall *)(void *, unsigned long, void *);
using Directory = int(__stdcall *)(const wchar_t *, void *);
using Wide = int(__stdcall *)(unsigned, unsigned long, const char *, int, wchar_t *, int);
struct Kernel
{
    File file;
    IO read, write;
    Name name;
    Move move;
    Delete remove;
    Flush flush;
    Pid pid;
    Heap heap;
    Alloc alloc;
    Free free;
    Directory directory;
    Wide wide;
};

bool resolve(Kernel &api)
{
    void *kernel = LoadLibraryA("kernel32.dll");
    if (!kernel)
        return false;
#define DWBSZ_API(field, type, name)                                                               \
    api.field = reinterpret_cast<type>(GetProcAddress(kernel, name))
    DWBSZ_API(file, File, "CreateFileW");
    DWBSZ_API(read, IO, "ReadFile");
    DWBSZ_API(write, IO, "WriteFile");
    DWBSZ_API(name, Name, "GetModuleFileNameW");
    DWBSZ_API(move, Move, "MoveFileExW");
    DWBSZ_API(remove, Delete, "DeleteFileW");
    DWBSZ_API(flush, Flush, "FlushFileBuffers");
    DWBSZ_API(pid, Pid, "GetCurrentProcessId");
    DWBSZ_API(heap, Heap, "GetProcessHeap");
    DWBSZ_API(alloc, Alloc, "HeapAlloc");
    DWBSZ_API(free, Free, "HeapFree");
    DWBSZ_API(directory, Directory, "CreateDirectoryW");
    DWBSZ_API(wide, Wide, "MultiByteToWideChar");
#undef DWBSZ_API
    return api.file && api.read && api.write && api.name && api.move && api.remove && api.flush &&
           api.pid && api.heap && api.alloc && api.free && api.directory && api.wide;
}

bool equal(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

bool append(wchar_t *out, size_t capacity, const wchar_t *text)
{
    size_t at = 0;
    while (at < capacity && out[at])
        ++at;
    for (size_t i = 0; text[i]; ++i)
    {
        if (at + 1 >= capacity)
            return false;
        out[at++] = text[i];
    }
    if (at >= capacity)
        return false;
    out[at] = 0;
    return true;
}

// Byte equality against the hash-bound executable resource verifies both
// content and exact length before a native database request can see it.
bool verify(const Kernel &api, const wchar_t *path, const uint8_t *bytes, uint32_t size)
{
    void *handle = api.file(path, 0x80000000, 1, nullptr, 3, 0x80, nullptr);
    if (handle == reinterpret_cast<void *>(~uintptr_t{0}))
        return false;
    uint8_t buffer[1024];
    bool same = true;
    for (uint32_t at = 0; same && at < size;)
    {
        uint32_t wanted = size - at;
        if (wanted > sizeof(buffer))
            wanted = sizeof(buffer);
        unsigned long got = 0;
        same = api.read(handle, buffer, wanted, &got, nullptr) && got == wanted;
        for (uint32_t i = 0; same && i < wanted; ++i)
            same = buffer[i] == bytes[at + i];
        at += wanted;
    }
    unsigned long extra = 0;
    same = same && api.read(handle, buffer, 1, &extra, nullptr) && !extra;
    CloseHandle(handle);
    return same;
}

bool writeAtomic(const Kernel &api, const wchar_t *path, const uint8_t *bytes, uint32_t size)
{
    if (verify(api, path, bytes, size))
        return true;
    wchar_t temporary[640]{};
    if (!append(temporary, 640, path) || !append(temporary, 640, L".tmp-"))
        return false;
    wchar_t suffix[9]{};
    const unsigned long pid = api.pid();
    for (unsigned i = 0; i < 8; ++i)
        suffix[i] = L"0123456789abcdef"[(pid >> ((7 - i) * 4)) & 15];
    if (!append(temporary, 640, suffix))
        return false;
    // Only the content-addressed overlay's own temporary path is replaced.
    void *handle = api.file(temporary, 0x40000000, 0, nullptr, 2, 0x80, nullptr);
    if (handle == reinterpret_cast<void *>(~uintptr_t{0}))
        return false;
    unsigned long written = 0;
    const bool ok = api.write(handle, const_cast<uint8_t *>(bytes), size, &written, nullptr) &&
                    written == size && api.flush(handle);
    CloseHandle(handle);
    if (!ok || !verify(api, temporary, bytes, size))
    {
        api.remove(temporary);
        return false;
    }
    // Normally these content-addressed names do not exist yet. Preserve a
    // modified copy before repairing it, including when an older updater has
    // installed the EXE without its companion files. Never replace a backup.
    wchar_t backup[640]{};
    bool backedUp = false;
    handle = api.file(path, 0, 7, nullptr, 3, 0x80, nullptr);
    if (handle != reinterpret_cast<void *>(~uintptr_t{0}))
    {
        CloseHandle(handle);
        size_t parent = 0;
        for (size_t i = 0; path[i]; ++i)
            if (path[i] == L'\\')
                parent = i + 1;
        wchar_t folder[640]{};
        if (!parent || parent >= 640)
        {
            api.remove(temporary);
            return false;
        }
        for (size_t i = 0; i < parent; ++i)
            folder[i] = path[i];
        if (!append(folder, 640, L"replay-dw-backups"))
        {
            api.remove(temporary);
            return false;
        }
        api.directory(folder, nullptr);
        for (unsigned attempt = 0; attempt < 16 && !backedUp; ++attempt)
        {
            backup[0] = 0;
            wchar_t index[4] = { L'-', L"0123456789abcdef"[attempt >> 4],
                                L"0123456789abcdef"[attempt & 15], 0 };
            if (!append(backup, 640, folder) || !append(backup, 640, L"\\") ||
                !append(backup, 640, path + parent) ||
                !append(backup, 640, L".original-") || !append(backup, 640, suffix) ||
                !append(backup, 640, index))
                break;
            backedUp = api.move(path, backup, 8) != 0;
        }
        if (!backedUp)
        {
            api.remove(temporary);
            return false;
        }
    }
    // No REPLACE_EXISTING: another process's file or a file we could not open
    // must not be silently overwritten. Failed installation restores the old
    // path when possible; its backup remains recoverable if restoration fails.
    const bool installed = api.move(temporary, path, 8) != 0;
    if (!installed)
    {
        api.remove(temporary);
        if (backedUp)
            api.move(backup, path, 8);
    }
    return installed && verify(api, path, bytes, size);
}

bool stagePair(const Kernel &api, const wchar_t *directory, const wchar_t *zone,
               const uint8_t *fastfileBytes, uint32_t fastfileSize, const uint8_t *patchBytes,
               uint32_t patchSize)
{
    wchar_t fastfile[640]{}, patch[640]{};
    if (!append(fastfile, 640, directory) || !append(fastfile, 640, L"\\") ||
        !append(fastfile, 640, zone) || !append(patch, 640, fastfile) ||
        !append(fastfile, 640, L".ff") || !append(patch, 640, L".fp"))
        return false;
    return writeAtomic(api, fastfile, fastfileBytes, fastfileSize) &&
           writeAtomic(api, patch, patchBytes, patchSize) &&
           verify(api, fastfile, fastfileBytes, fastfileSize) &&
           verify(api, patch, patchBytes, patchSize);
}

bool installationName(const char *name, const char *zone, wchar_t *wide)
{
    if (!name)
        return false;
    size_t length = 0, zoneLength = 0;
    for (; zone[zoneLength]; ++zoneLength) {}
    for (; name[length]; ++length)
    {
        const char c = name[length];
        if (length >= 63 || !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
        wide[length] = c;
    }
    if (length < zoneLength || length - zoneLength > 17 ||
        (length != zoneLength && name[length - zoneLength - 1] != '_'))
        return false;
    return equal(name + length - zoneLength, zone);
}

bool installationDirectory(const Kernel &api, const wchar_t *root, const char *name,
                           const char *relative, wchar_t *directory)
{
    if (!relative || !append(directory, 512, root))
        return false;
    if (*relative)
    {
        if (!append(directory, 512, L"\\"))
            return false;
        wchar_t wide[64]{};
        size_t length = 0;
        for (; relative[length]; ++length)
        {
            const char c = relative[length];
            if (length + 1 >= 64 || !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
                return false;
            wide[length] = c;
        }
        if (!append(directory, 512, wide))
            return false;
    }
    // DB_File_OpenDBFile selects current-language folder1, current-region
    // folder7, otherwise folder0. Foreign companions are prestaged in their
    // target-derived future-locale directory; active files must match the
    // complete native path builder before any owned file is written there.
    const unsigned folder = DWBSZ_IsLocalized(name) ? 1u : DWBSZ_IsRegional(name) ? 7u : 0u;
    if (folder || !*relative)
    {
        char native[512]{};
        wchar_t expected[512]{};
        DWBSZ_BuildAbsPath(native, 512, folder, "", "");
        const int count = api.wide(65001, 8, native, -1, expected, 512);
        if (count <= 1)
            return false;
        unsigned length = unsigned(count - 1);
        while (length && (expected[length - 1] == L'\\' || expected[length - 1] == L'/'))
            expected[--length] = 0;
        unsigned at = 0;
        for (; directory[at] && expected[at]; ++at)
        {
            wchar_t a = directory[at], b = expected[at];
            if (a >= L'A' && a <= L'Z') a += L'a' - L'A';
            if (b >= L'A' && b <= L'Z') b += L'a' - L'A';
            if (a != b)
                return false;
        }
        if (directory[at] != expected[at])
            return false;
    }
    api.directory(directory, nullptr);
    return true;
}

bool stage(const Kernel &api, const DWBotStyleScriptPackage &package,
           const char *prefix = "dw_bot_styles_mp_")
{
    if (!package.zoneName || !package.fastfile || !package.patch || !package.fastfileBytes ||
        !package.patchBytes || !package.emptyFastfile || !package.emptyFastfileBytes ||
        !package.emptyPatch || !package.emptyPatchBytes || !package.installationNames ||
        !package.installationDirectories ||
        !package.installationNameCount || package.installationNameCount > 128 || package.reserved)
        return false;
    size_t length = 0;
    for (; package.zoneName[length]; ++length)
    {
        const char c = package.zoneName[length];
        if (length + 1 >= 80 || !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    size_t prefixLength = 0;
    while (prefix[prefixLength])
        ++prefixLength;
    if (length != prefixLength + 16)
        return false;
    for (size_t i = 0; i < prefixLength; ++i)
        if (package.zoneName[i] != prefix[i])
            return false;
    wchar_t directory[512]{};
    unsigned long count = api.name(nullptr, directory, 512);
    if (!count || count >= 512)
        return false;
    while (count && directory[count - 1] != L'\\')
        --count;
    if (!count)
        return false;
    directory[count] = 0;
    if (!append(directory, 512, L"zone"))
        return false;
    // Already-existing native zone directories are accepted by file open;
    // an unsuccessful create is not mistaken for successful staging.
    api.directory(directory, nullptr);
    // Replay propagates the requested failure mode to every dependency.
    // Empty native zones satisfy those required reads in every locale and
    // precompiled-shader mode without adding or replacing any assets.
    // Stage every owned locale from the same generated installation manifest
    // used by the updater. An old helper can bootstrap this EXE without a second
    // restart just to obtain its currently unused language/region companions.
    unsigned primaryCount = 0;
    for (uint32_t i = 0; i < package.installationNameCount; ++i)
    {
        wchar_t name[64]{};
        wchar_t nativeDirectory[512]{};
        if (!installationName(package.installationNames[i], package.zoneName, name))
            return false;
        if (!installationDirectory(api, directory, package.installationNames[i],
                                   package.installationDirectories[i], nativeDirectory))
            return false;
        const bool primary = equal(package.installationNames[i], package.zoneName);
        if (primary)
            ++primaryCount;
        if (!stagePair(api, nativeDirectory, name,
                       primary ? package.fastfile : package.emptyFastfile,
                       primary ? package.fastfileBytes : package.emptyFastfileBytes,
                       primary ? package.patch : package.emptyPatch,
                       primary ? package.patchBytes : package.emptyPatchBytes))
            return false;
    }
    return primaryCount == 1;
}

// Published custom maps' lobby and loading images (tools/prepare-map-images-
// package.py): the zone, its techsets_ zone and empty companions, staged with
// the same native installation policy as the bot-style overlay.
bool stageMapImages(const Kernel &api)
{
    using namespace DWMapImages;
    wchar_t directory[512]{};
    unsigned long count = api.name(nullptr, directory, 512);
    if (!count || count >= 512)
        return false;
    while (count && directory[count - 1] != L'\\')
        --count;
    if (!count)
        return false;
    directory[count] = 0;
    if (!append(directory, 512, L"zone"))
        return false;
    api.directory(directory, nullptr);
    constexpr uint32_t entries = sizeof(InstallationNames) / sizeof(*InstallationNames);
    static_assert(entries == sizeof(InstallationDirectories) / sizeof(*InstallationDirectories));
    char techsets[80] = "techsets_";
    for (size_t at = 9, i = 0; ZoneName[i] && at + 1 < sizeof(techsets); ++at, ++i)
        techsets[at] = ZoneName[i];
    unsigned primaryCount = 0, techsetsCount = 0;
    for (uint32_t i = 0; i < entries; ++i)
    {
        wchar_t name[64]{};
        wchar_t nativeDirectory[512]{};
        if (!installationName(InstallationNames[i], ZoneName, name) ||
            !installationDirectory(api, directory, InstallationNames[i], InstallationDirectories[i],
                                   nativeDirectory))
            return false;
        const bool primary = equal(InstallationNames[i], ZoneName);
        const bool materials = equal(InstallationNames[i], techsets);
        primaryCount += primary;
        techsetsCount += materials;
        const bool staged =
            primary ? stagePair(api, nativeDirectory, name, Fastfile, sizeof(Fastfile), Patch,
                                sizeof(Patch))
            : materials ? stagePair(api, nativeDirectory, name, TechsetsFastfile,
                                    sizeof(TechsetsFastfile), TechsetsPatch, sizeof(TechsetsPatch))
                        : stagePair(api, nativeDirectory, name, EmptyFastfile, sizeof(EmptyFastfile),
                                    EmptyPatch, sizeof(EmptyPatch));
        if (!staged)
            return false;
    }
    return primaryCount == 1 && techsetsCount == 1;
}
} // namespace

extern "C" bool DW_MapImages_PublishedListed(const char *id)
{
    for (const char *map : DWMapImages::MapIds)
        if (equal(map, id))
            return true;
    return false;
}

namespace
{
// replay-dw-client.log: "<prefix> load=<flags> name:flags ..." for zone requests.
void logZoneRequest(const char *prefix, const DWBotStyleFastfileInfo *info, uint32_t count,
                    uint32_t loadFlags)
{
    char line[1024];
    unsigned used = 0;
    const auto put = [&](const char *text) {
        for (; text && *text && used + 1 < sizeof(line); ++text)
            line[used++] = *text;
    };
    const auto hex = [&](uint32_t value) {
        char digits[11] = "0x";
        for (int i = 0; i < 8; ++i)
            digits[2 + i] = "0123456789abcdef"[(value >> (28 - 4 * i)) & 15];
        digits[10] = 0;
        put(digits);
    };
    put(prefix);
    put(" load=");
    hex(loadFlags);
    for (uint32_t i = 0; info && i < count && used + 40 < sizeof(line); ++i)
    {
        put(" ");
        put(info[i].name);
        put(":");
        hex(info[i].zoneFlags);
    }
    line[used] = 0;
    DW_LocalBackend_LogLine(line);
}

bool startsWith(const char *text, const char *prefix)
{
    for (; *prefix; ++text, ++prefix)
        if (*text != *prefix)
            return false;
    return true;
}
} // namespace

extern "C" void DW_BotStyleZone_LoadFastfiles(const DWBotStyleFastfileInfo *info, uint32_t count,
                                              uint32_t loadFlags, bool loadServerZone)
{
    logZoneRequest("DW_ZONE_REQUEST", info, count, loadFlags);
    // Custom map loading images (iw8-zonetool build-map-images) are installed
    // like the bot overlay: native zone folders, with every companion zone and
    // header-only patch that the native failure mode requires. The published
    // maps' zone ships in this executable (dw_map_images, staged once per run);
    // an owner-built mw120r_map_images (every installed map) may also exist.
    static const char kMapImagesZone[] = "mw120r_map_images";
    static int s_publishedImages; // 0 not staged yet, 1 staged, -1 staging failed
    const char *const publishedImagesZone = DWMapImages::ZoneName;
    const DWBotStyleScriptPackage *package = DW_BotStyleScripts_GetPackage();
    const DWBotStyleScriptPackage &inspectPackage = DWWeaponInspectPackage::Package;
    const DWBotStyleFastfileInfo *common = nullptr, *ui = nullptr, *boot = nullptr;
    bool supplied = false, imagesSupplied = false, publishedSupplied = false;
    bool inspectSupplied = false;
    for (uint32_t i = 0; info && i < count; ++i)
    {
        if (equal(info[i].name, "common_base_mp"))
            common = &info[i];
        if (equal(info[i].name, "ui"))
            ui = &info[i];
        if (equal(info[i].name, "common"))
            boot = &info[i];
        if (package && equal(info[i].name, package->zoneName))
            supplied = true;
        if (equal(info[i].name, inspectPackage.zoneName))
            inspectSupplied = true;
        if (equal(info[i].name, kMapImagesZone))
            imagesSupplied = true;
        if (equal(info[i].name, publishedImagesZone))
            publishedSupplied = true;
    }
    // Map art loads with the frontend UI zones at startup, where the stock
    // loading_<map>_bg images live (ui.ff). common_base_mp is the last of the
    // multiplayer game-mode modules (global, core, common, base): images loaded
    // with it drew white in the lobby until those gigabytes had loaded (owner
    // 2026-10-16). It remains the anchor if no UI request is seen.
    // The map art zone follows whichever phase loads it, so it must come back
    // with the next phase: a match unloads it (white loading screen, owner
    // 2026-10-16) and the frontend after a match never re-requests ui (white
    // lobby). Without ui or common_base_mp, a map or frontend zone (mp_*) of
    // the request anchors it; it is re-added whenever fully unloaded.
    // Logged requests (replay-dw-client.log, owner 2026-10-16): the boot request
    // is "ui_boot:0x40 global:0x1 common:0x1 ui:0x40 ... mp_frontend3:0x80";
    // ComFastFile's frontend unload frees the 0x40/0x80 zones at match start, so
    // map art copied from ui's record was gone before the loading screen drew.
    // The boot "common" record (0x1, like code_post_gfx) is never unloaded, and
    // it shares ui's request, so the lobby still has the art at startup.
    const DWBotStyleFastfileInfo *imageAnchor = boot ? boot : ui ? ui : common;
    for (uint32_t i = 0; !imageAnchor && info && i < count; ++i)
    {
        // Transient streaming zones (mp_*_tr) are never anchors.
        const char *name = info[i].name;
        unsigned length = 0;
        while (name && name[length])
            ++length;
        if (name && startsWith(name, "mp_") &&
            !(length > 3 && name[length - 3] == '_' && name[length - 2] == 't' && name[length - 1] == 'r'))
            imageAnchor = &info[i];
    }
    // Native polling includes pending, paused, cancelled and fully loaded zones.
    // A later unload returns state zero, allowing the next request to load the
    // same overlay again. No process-lifetime 'loaded' latch is used.
    bool bot = common && package && !supplied && DWBSZ_PollFastfileState(package->zoneName) == 0;
    bool inspection = common && !inspectSupplied &&
                      DWBSZ_PollFastfileState(inspectPackage.zoneName) == 0;
    const bool images = imageAnchor && !imagesSupplied && DW_MapImages_ZoneInstalled() &&
                        DWBSZ_PollFastfileState(kMapImagesZone) == 0;
    bool published = imageAnchor && !publishedSupplied && s_publishedImages >= 0 &&
                     DWBSZ_PollFastfileState(publishedImagesZone) == 0;
    if (!bot && !images && !published && !inspection)
    {
        DW_BotStyleZone_LoadFastfilesNative(info, count, loadFlags, loadServerZone);
        return;
    }
    Kernel api{};
    if (!resolve(api) || count >= UINT32_MAX - 4 ||
        static_cast<size_t>(count) + 4 > SIZE_MAX / sizeof(DWBotStyleFastfileInfo))
    {
        DWBSZ_Print(10, "DW: native overlay request failed; original zone request retained.\n");
        DW_BotStyleZone_LoadFastfilesNative(info, count, loadFlags, loadServerZone);
        return;
    }
    if (bot && !stage(api, *package))
    {
        DWBSZ_Print(
            10, "DW: bot style native overlay staging failed; original zone request retained.\n");
        bot = false;
    }
    if (inspection && !stage(api, inspectPackage, "dw_weapon_inspect_mp_"))
    {
        DWBSZ_Print(10, "DW: inspection animation staging failed; inspection unavailable.\n");
        inspection = false;
    }
    if (published && !s_publishedImages)
    {
        s_publishedImages = stageMapImages(api) ? 1 : -1;
        if (s_publishedImages < 0)
            DWBSZ_Print(10, "DW: published map image zone staging failed; map images omitted.\n");
    }
    published = published && s_publishedImages > 0;
    if (!bot && !images && !published && !inspection)
    {
        DW_BotStyleZone_LoadFastfilesNative(info, count, loadFlags, loadServerZone);
        return;
    }
    void *heap = api.heap();
    auto *augmented = static_cast<DWBotStyleFastfileInfo *>(
        api.alloc(heap, 0, (static_cast<size_t>(count) + 4) * sizeof(DWBotStyleFastfileInfo)));
    if (!augmented)
    {
        DWBSZ_Print(10, "DW: native overlay request allocation failed.\n");
        DW_BotStyleZone_LoadFastfilesNative(info, count, loadFlags, loadServerZone);
        return;
    }
    uint32_t at = 0;
    for (uint32_t i = 0; i < count; ++i)
    {
        if (&info[i] == common && inspection)
        {
            // Register real XAnims and their ANM names before the common
            // module completes the native client/server constant-string map.
            augmented[at] = info[i];
            augmented[at++].name = inspectPackage.zoneName;
        }
        if (&info[i] == common && bot)
        {
            // Same-group duplicates are discarded by native DB_LinkXAssetEntry.
            // Register the three owned scripts first; common_base_mp then keeps
            // those native entries while registering every other stock asset.
            augmented[at] = info[i];
            augmented[at++].name = package->zoneName;
        }
        if (&info[i] == imageAnchor)
        {
            // The published zone first: an owner-built zone that names the same
            // images links after it and its duplicates are discarded.
            if (published)
            {
                augmented[at] = info[i];
                augmented[at++].name = publishedImagesZone;
            }
            if (images)
            {
                augmented[at] = info[i];
                augmented[at++].name = kMapImagesZone;
            }
        }
        augmented[at++] = info[i];
    }
    if (bot)
        DWBSZ_Print(10, "DW: native bot style overlay '%s' precedes common_base_mp.\n",
                    package->zoneName);
    if (inspection)
        DWBSZ_Print(10, "DW: inspection animation zone '%s' precedes common_base_mp.\n",
                    inspectPackage.zoneName);
    if (published)
        DWBSZ_Print(10, "DW: published map image zone '%s' precedes %s.\n", publishedImagesZone,
                    imageAnchor->name);
    if (images)
        DWBSZ_Print(10, "DW: custom map image zone '%s' precedes %s.\n", kMapImagesZone,
                    imageAnchor->name);
    if (images || published)
        logZoneRequest("DW_ZONE_MAP_IMAGES added before", imageAnchor, 1, loadFlags);
    // The complete original routine copies each record into its native queue;
    // caller memory is not retained after this four-argument call returns.
    DW_BotStyleZone_LoadFastfilesNative(augmented, at, loadFlags, loadServerZone);
    api.free(heap, 0, augmented);
}
