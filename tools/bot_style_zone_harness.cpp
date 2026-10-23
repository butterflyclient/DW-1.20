// Compile the production wrapper unchanged, then model only native/OS boundaries.
#include "../integration/replay/DW_BotStyleZone.cpp"
namespace
{
struct Entry
{
    wchar_t name[1200];
    uint8_t bytes[400000]; // the published map image zone is ~320 KB
    unsigned size, cursor;
    bool exists;
} files[128];
DWBotStyleScriptPackage package = DWBotStyleScripts::Package;
DWBotStyleFastfileInfo captured[10], allocation[10];
unsigned nativeCalls, seenCount, seenFlags, state, writes, moves, frees, messages, failure;
unsigned reads, nativeMissing;
unsigned backupMoves, restoreMoves;
const char *regionCode = "ww", *languageCode = "eng";
const char *regionDirectory = "worldwide", *languageDirectory = "english";
bool seenServer, packagePresent = true;
bool mapImages;
unsigned mapImagesState, publishedState = 99;
unsigned inspectionState = 99;
unsigned gulagState = 99, operatorsState = 99;
unsigned commonMpState = 99, globalStreamMpState = 99;
bool operatorsInstalled;
const DWBotStyleFastfileInfo *seenPointer;
bool sameWide(const wchar_t *a, const wchar_t *b)
{
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}
bool containsWide(const wchar_t *text, const wchar_t *part)
{
    for (unsigned at = 0; text[at]; ++at)
    {
        unsigned length = 0;
        while (part[length] && text[at + length] == part[length])
            ++length;
        if (!part[length])
            return true;
    }
    return false;
}
Entry *fileAt(const wchar_t *name)
{
    for (auto &file : files)
        if (file.exists && sameWide(file.name, name))
            return &file;
    return nullptr;
}
void copyWide(wchar_t *a, const wchar_t *b)
{
    unsigned i = 0;
    do
    {
        a[i] = b[i];
    } while (b[i++]);
}
void clear()
{
    for (auto &file : files)
    {
        file.exists = false;
        file.name[0] = 0;
        file.size = file.cursor = 0;
    }
    nativeCalls = seenCount = seenFlags = state = writes = moves = frees = messages = failure = 0;
    reads = nativeMissing = 0;
    backupMoves = restoreMoves = 0;
    package = DWBotStyleScripts::Package;
    packagePresent = true;
    mapImages = false;
    mapImagesState = 0;
    publishedState = 99;
    inspectionState = 99;
    gulagState = operatorsState = 99;
    operatorsInstalled = false;
    commonMpState = globalStreamMpState = 99;
}
void *__stdcall create(const wchar_t *name, unsigned long access, unsigned long, void *,
                       unsigned long disposition, unsigned long, void *)
{
    if (failure == 1)
        return reinterpret_cast<void *>(~uintptr_t{0});
    Entry *found = nullptr;
    for (auto &file : files)
        if (file.name[0] && sameWide(file.name, name))
        {
            found = &file;
            break;
        }
    if (disposition == 3 && (!found || !found->exists))
        return reinterpret_cast<void *>(~uintptr_t{0});
    if (!found)
        for (auto &file : files)
            if (!file.name[0])
            {
                found = &file;
                copyWide(file.name, name);
                break;
            }
    if (!found)
        return reinterpret_cast<void *>(~uintptr_t{0});
    if (access == 0x40000000 && disposition == 2)
    {
        found->exists = true;
        found->size = 0;
    }
    found->cursor = 0;
    return found;
}
int __stdcall readFile(void *handle, void *out, unsigned long count, unsigned long *got, void *)
{
    ++reads;
    auto &file = *static_cast<Entry *>(handle);
    *got = count;
    if (*got > file.size - file.cursor)
        *got = file.size - file.cursor;
    for (unsigned i = 0; i < *got; ++i)
        static_cast<uint8_t *>(out)[i] = file.bytes[file.cursor + i];
    file.cursor += *got;
    return failure != 2;
}
int __stdcall writeFile(void *handle, void *input, unsigned long count, unsigned long *written,
                        void *)
{
    ++writes;
    auto &file = *static_cast<Entry *>(handle);
    *written = failure == 3 ? count - 1 : count;
    if (*written > sizeof(file.bytes))
        return 0;
    for (unsigned i = 0; i < *written; ++i)
        file.bytes[i] = static_cast<uint8_t *>(input)[i];
    file.size = *written;
    return 1;
}
int __stdcall moveFile(const wchar_t *from, const wchar_t *to, unsigned long flags)
{
    ++moves;
    if (failure == 4 || (flags != 8 && flags != 9))
        return 0;
    Entry *source = nullptr, *dest = nullptr;
    for (auto &file : files)
    {
        if (sameWide(file.name, from))
            source = &file;
        if (sameWide(file.name, to))
            dest = &file;
    }
    if (!source || !source->exists)
        return 0;
    // Match MoveFileExW: WRITE_THROUGH alone never replaces an existing path.
    if (dest && dest->exists && !(flags & 1))
        return 0;
    if (failure == 8 && containsWide(from, L".tmp-"))
        return 0; // fail installation after preserving the original; allow rollback
    const bool toBackup = containsWide(to, L"\\replay-dw-backups\\");
    const bool fromBackup = containsWide(from, L"\\replay-dw-backups\\");
    if (dest)
    {
        dest->name[0] = 0;
        dest->exists = false;
    }
    copyWide(source->name, to);
    backupMoves += toBackup;
    restoreMoves += fromBackup && !toBackup;
    return 1;
}
int __stdcall removeFile(const wchar_t *name)
{
    for (auto &file : files)
        if (sameWide(file.name, name))
        {
            file.exists = false;
            file.name[0] = 0;
        }
    return 1;
}
int __stdcall flush(void *)
{
    return failure != 5;
}
unsigned long __stdcall moduleName(void *, wchar_t *out, unsigned long capacity)
{
    const wchar_t name[] = L"E:\\DW\\IW8\\data\\offline-zone-harness\\game.exe";
    if (capacity < sizeof(name) / sizeof(*name))
        return 0;
    copyWide(out, name);
    return sizeof(name) / sizeof(*name) - 1;
}
unsigned long __stdcall pid()
{
    return 123;
}
void *__stdcall heap()
{
    return allocation;
}
void *__stdcall alloc(void *owner, unsigned long flags, size_t size)
{
    return owner == allocation && flags == 0 && size <= sizeof(allocation) && failure != 6
               ? allocation
               : nullptr;
}
int __stdcall free(void *owner, unsigned long flags, void *value)
{
    if (owner == allocation && !flags && value == allocation)
        ++frees;
    return 1;
}
int __stdcall directory(const wchar_t *, void *)
{
    return 1;
}
int __stdcall wide(unsigned codepage, unsigned long flags, const char *input, int size,
                   wchar_t *output, int capacity)
{
    if (codepage != 65001 || flags != 8 || size != -1)
        return 0;
    int i = 0;
    do
    {
        if (i >= capacity)
            return 0;
        output[i] = static_cast<unsigned char>(input[i]);
    } while (input[i++]);
    return i;
}
bool prefix(const char *name, const char *code)
{
    unsigned i = 0;
    for (; code[i]; ++i)
        if (name[i] != code[i])
            return false;
    return name[i] == '_';
}
void *__stdcall load(const char *)
{
    return reinterpret_cast<void *>(1);
}
int __stdcall close(void *)
{
    return 1;
}
void *__stdcall address(void *, const char *name)
{
#define API(n, f)                                                                                  \
    if (equal(name, n))                                                                            \
    return reinterpret_cast<void *>(&f)
    API("CreateFileW", create);
    API("ReadFile", readFile);
    API("WriteFile", writeFile);
    API("MoveFileExW", moveFile);
    API("DeleteFileW", removeFile);
    API("FlushFileBuffers", flush);
    API("GetModuleFileNameW", moduleName);
    API("GetCurrentProcessId", pid);
    API("GetProcessHeap", heap);
    API("HeapAlloc", alloc);
    API("HeapFree", free);
    API("CreateDirectoryW", directory);
    API("MultiByteToWideChar", wide);
#undef API
    return nullptr;
}
} // namespace
extern "C"
{
    void *(__stdcall *__imp_LoadLibraryA)(const char *) = load;
    void *(__stdcall *__imp_GetProcAddress)(void *, const char *) = address;
    int(__stdcall *__imp_CloseHandle)(void *) = close;
    void *memset(void *out, int value, size_t size)
    {
        for (size_t i = 0; i < size; ++i)
            static_cast<uint8_t *>(out)[i] = static_cast<uint8_t>(value);
        return out;
    }
    void *memcpy(void *out, const void *in, size_t size)
    {
        for (size_t i = 0; i < size; ++i)
            static_cast<uint8_t *>(out)[i] = static_cast<const uint8_t *>(in)[i];
        return out;
    }
    const DWBotStyleScriptPackage *DW_BotStyleScripts_GetPackage()
    {
        return packagePresent ? &package : nullptr;
    }
    unsigned DWBSZ_PollFastfileState(const char *name)
    {
        if (equal(name, "mw120r_map_images"))
            return mapImagesState;
        if (equal(name, DWMapImages::ZoneName))
            return publishedState;
        if (equal(name, DWWeaponInspectPackage::Package.zoneName))
            return inspectionState;
        if (equal(name, "common_mp"))
            return commonMpState;
        if (equal(name, "global_stream_mp"))
            return globalStreamMpState;
        if (equal(name, DWCustomOperatorsPackage::Package.zoneName))
            return operatorsState;
        if (equal(name, DWGulagNavPackage::Package.zoneName))
            return gulagState;
        return equal(name, package.zoneName) ? state : 99;
    }
    void DW_CustomOperators_ZoneInstalled(bool installed) { operatorsInstalled = installed; }
    bool DW_MapImages_ZoneInstalled()
    {
        return mapImages;
    }
    const char *DWBSZ_CurrentRegionCode()
    {
        return regionCode;
    }
    const char *DWBSZ_CurrentLanguageCode()
    {
        return languageCode;
    }
    bool DWBSZ_IsLocalized(const char *name) { return prefix(name, languageCode); }
    bool DWBSZ_IsRegional(const char *name) { return prefix(name, regionCode); }
    void DWBSZ_BuildAbsPath(char *output, int capacity, unsigned folder, const char *name,
                           const char *extension)
    {
        const char *root = failure == 7 ? "E:\\outside\\" : "E:\\DW\\IW8\\data\\offline-zone-harness\\zone\\";
        const char *directory = folder == 1 ? languageDirectory : folder == 7 ? regionDirectory : "";
        int at = 0;
        const char *parts[] = {root, directory, *directory ? "\\" : "", name, extension};
        for (const char *text : parts)
            for (unsigned i = 0; text[i]; ++i)
            {
                if (at + 1 >= capacity)
                    return;
                output[at++] = text[i];
            }
        output[at] = 0;
    }
    void DWBSZ_Print(int, const char *, ...)
    {
        ++messages;
    }
    void DW_LocalBackend_LogLine(const char *)
    {
    }
    void DW_BotStyleZone_LoadFastfilesNative(const DWBotStyleFastfileInfo *info, uint32_t count,
                                             uint32_t flags, bool server)
    {
        ++nativeCalls;
        seenPointer = info;
        seenCount = count;
        seenFlags = flags;
        seenServer = server;
        if (count <= 10)
            for (unsigned i = 0; i < count; ++i)
                captured[i] = info[i];
        const DWBotStyleScriptPackage *resources[] = {
            &package, &DWWeaponInspectPackage::Package, &DWGulagNavPackage::Package,
            &DWCustomOperatorsPackage::Package};
        for (const auto *resource : resources)
        {
            bool overlay = false;
            for (unsigned i = 0; i < count; ++i)
                overlay |= equal(info[i].name, resource->zoneName);
            if (!overlay)
                continue;
            // Model the native consumer's actual current-locale search path.
            const char *codes[] = {regionCode, languageCode};
            for (const char *code : codes)
            {
                char name[128]{};
                unsigned at = 0;
                for (unsigned i = 0; code[i]; ++i) name[at++] = code[i];
                name[at++] = '_';
                for (unsigned i = 0; resource->zoneName[i]; ++i) name[at++] = resource->zoneName[i];
                char path[512]{};
                DWBSZ_BuildAbsPath(path, 512, equal(code, languageCode) ? 1 : 7, name, ".ff");
                wchar_t expected[512]{};
                wide(65001, 8, path, -1, expected, 512);
                bool found = false;
                for (auto &file : files) found |= file.exists && sameWide(file.name, expected);
                nativeMissing += !found;
            }
        }
    }
    __declspec(dllexport) int Test_Run()
    {
#define CHECK(c)                                                                                   \
    if (!(c))                                                                                      \
    return __LINE__
        clear();
        DWBotStyleFastfileInfo stock[] = {{"before", 3, 4, 5, 6},
                                          {"common_base_mp", 0x8008123, 7, 88, 0x12345678},
                                          {"after", 9, 10, 11, 12}};
        DW_BotStyleZone_LoadFastfiles(stock, 3, 3, true);
        CHECK(nativeCalls == 1 && seenCount == 4 && seenFlags == 3 && seenServer && frees == 1 &&
              writes == 2 * package.installationNameCount && moves == writes);
        unsigned existing = 0;
        for (const auto &file : files)
            if (file.exists)
                ++existing;
        CHECK(existing == writes && package.installationNameCount == 10);
        CHECK(!nativeMissing);
        CHECK(equal(captured[0].name, "before") && equal(captured[1].name, package.zoneName) &&
              equal(captured[2].name, "common_base_mp") && equal(captured[3].name, "after"));
        CHECK(captured[1].zoneFlags == stock[1].zoneFlags && captured[1].failureMode == 7 &&
              captured[1].priority == 88 && captured[1].reserved == 0x12345678);
        CHECK(stock[1].name != package.zoneName && stock[1].reserved == 0x12345678);
        unsigned oldWrites = writes;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 2, false);
        CHECK(nativeCalls == 2 && seenCount == 4 && seenFlags == 2 && !seenServer &&
              writes == oldWrites && frees == 2);
        // Native polling controls every lifecycle; no cached loaded latch.
        for (unsigned s = 1; s <= 4; ++s)
        {
            state = s;
            unsigned oldReads = reads;
            DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
            CHECK(seenPointer == stock && seenCount == 3 && writes == oldWrites);
            CHECK(reads == oldReads);
        }
        state = 0;
        wchar_t stalePath[1200]{};
        copyWide(stalePath, files[0].name);
        CHECK(files[0].size == package.fastfileBytes && files[0].size > 100);
        files[0].bytes[100] ^= 0x40;
        const unsigned oldMoves = moves;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 1, false);
        CHECK(seenCount == 4 && writes == oldWrites + 1 && moves == oldMoves + 2 &&
              backupMoves == 1 && !restoreMoves);
        wchar_t backupPath[1200] = L"E:\\DW\\IW8\\data\\offline-zone-harness\\zone\\replay-dw-backups\\";
        const wchar_t *basename = stalePath;
        for (unsigned i = 0; stalePath[i]; ++i)
            if (stalePath[i] == L'\\')
                basename = &stalePath[i + 1];
        unsigned backupAt = 0;
        while (backupPath[backupAt]) ++backupAt;
        for (unsigned i = 0; basename[i]; ++i) backupPath[backupAt++] = basename[i];
        const wchar_t backupSuffix[] = L".original-0000007b-00";
        for (unsigned i = 0; backupSuffix[i]; ++i) backupPath[backupAt++] = backupSuffix[i];
        backupPath[backupAt] = 0;
        Entry *retained = fileAt(backupPath);
        Entry *repaired = fileAt(stalePath);
        CHECK(retained && repaired && retained->size == package.fastfileBytes &&
              repaired->size == package.fastfileBytes);
        for (unsigned i = 0; i < package.fastfileBytes; ++i)
        {
            CHECK(retained->bytes[i] == (i == 100 ? uint8_t(package.fastfile[i] ^ 0x40) : package.fastfile[i]));
            CHECK(repaired->bytes[i] == package.fastfile[i]);
        }
        DWBotStyleFastfileInfo duplicate[] = {{"common_base_mp", 1, 2, 3, 4},
                                              {package.zoneName, 1, 2, 3, 4}};
        DW_BotStyleZone_LoadFastfiles(duplicate, 2, 15, true);
        CHECK(seenPointer == duplicate && seenCount == 2 && seenFlags == 15);
        for (unsigned mode = 1; mode <= 7; ++mode)
        {
            clear();
            failure = mode;
            DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
            CHECK(nativeCalls == 1 && seenPointer == stock && seenCount == 3 && messages == 1);
        }
        clear();
        package.zoneName = "../common_base_mp";
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenPointer == stock && !writes && messages == 1);
        clear();
        const char *invalidDirectories[] = {"../outside"};
        package.installationDirectories = invalidDirectories;
        package.installationNameCount = 1;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenPointer == stock && !writes && messages == 1);
        clear();
        const char *invalidNames[] = {"../common_base_mp"};
        package.installationNames = invalidNames;
        package.installationNameCount = 1;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenPointer == stock && !writes && messages == 1);
        clear();
        packagePresent = false;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenPointer == stock && !writes);
        clear();
        DW_BotStyleZone_LoadFastfiles(stock, 1, 2, true);
        CHECK(seenPointer == stock && seenCount == 1 && !writes);
        clear();
        DW_BotStyleZone_LoadFastfiles(nullptr, 0, 1, false);
        CHECK(!seenPointer && seenCount == 0 && !writes);
        // Installed custom map image zone: after the overlay, before common_base_mp,
        // with common_base_mp's record; only while native polling reports it absent.
        clear();
        mapImages = true;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 3, true);
        CHECK(nativeCalls == 1 && seenCount == 5 && frees == 1 && !nativeMissing);
        CHECK(equal(captured[0].name, "before") && equal(captured[1].name, package.zoneName) &&
              equal(captured[2].name, "mw120r_map_images") &&
              equal(captured[3].name, "common_base_mp") && equal(captured[4].name, "after"));
        CHECK(captured[2].zoneFlags == stock[1].zoneFlags && captured[2].failureMode == 7 &&
              captured[2].priority == 88 && captured[2].reserved == 0x12345678);
        state = 1;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenCount == 4 && equal(captured[1].name, "mw120r_map_images"));
        mapImagesState = 1;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenPointer == stock && seenCount == 3);
        clear();
        mapImages = true;
        packagePresent = false;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenCount == 4 && equal(captured[1].name, "mw120r_map_images") && !writes);
        clear();
        mapImages = true;
        failure = 1;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        CHECK(seenCount == 4 && equal(captured[1].name, "mw120r_map_images") && messages == 2);
        clear();
        DWBotStyleFastfileInfo supplied[] = {{"mw120r_map_images", 1, 2, 3, 4},
                                             {"common_base_mp", 1, 2, 3, 4}};
        mapImages = true;
        packagePresent = false;
        DW_BotStyleZone_LoadFastfiles(supplied, 2, 0, false);
        CHECK(seenPointer == supplied && seenCount == 2);
        // Map art loads with the frontend UI zones when a request names "ui",
        // with that record's flags, failure mode and priority.
        clear();
        mapImages = true;
        packagePresent = false;
        DWBotStyleFastfileInfo frontend[] = {{"before", 3, 4, 5, 6},
                                             {"ui", 0x40, 9, 77, 0x5555},
                                             {"after", 9, 10, 11, 12}};
        DW_BotStyleZone_LoadFastfiles(frontend, 3, 1, false);
        CHECK(seenCount == 4 && equal(captured[1].name, "mw120r_map_images") &&
              equal(captured[2].name, "ui") && !writes);
        CHECK(captured[1].zoneFlags == 0x40 && captured[1].failureMode == 9 &&
              captured[1].priority == 77 && captured[1].reserved == 0x5555);
        // The boot request's "common" record (flags 0x1, never unloaded) wins over
        // ui (0x40, freed by the frontend unload at match start).
        clear();
        mapImages = true;
        packagePresent = false;
        DWBotStyleFastfileInfo boot[] = {{"ui_boot", 0x40, 1, 2, 3}, {"common", 0x1, 4, 5, 6},
                                         {"ui", 0x40, 9, 77, 0x5555}};
        DW_BotStyleZone_LoadFastfiles(boot, 3, 2, false);
        CHECK(seenCount == 4 && equal(captured[1].name, "mw120r_map_images") &&
              equal(captured[2].name, "common") && captured[1].zoneFlags == 0x1 &&
              captured[1].failureMode == 4 && captured[1].priority == 5);
        // Without ui or common_base_mp, a map or frontend zone (mp_*) anchors the
        // map art again once it has been unloaded (a match unloads it); a
        // transient mp_*_tr zone never does.
        clear();
        mapImages = true;
        packagePresent = false;
        DWBotStyleFastfileInfo match[] = {{"mp_nuketown", 0x21, 2, 3, 4}, {"after", 9, 10, 11, 12}};
        DW_BotStyleZone_LoadFastfiles(match, 2, 1, false);
        CHECK(seenCount == 3 && equal(captured[0].name, "mw120r_map_images") &&
              equal(captured[1].name, "mp_nuketown") && captured[0].zoneFlags == 0x21);
        clear();
        mapImages = true;
        packagePresent = false;
        DWBotStyleFastfileInfo transient[] = {{"mp_av_attachment_tr", 0x21, 2, 3, 4}};
        DW_BotStyleZone_LoadFastfiles(transient, 1, 1, false);
        CHECK(seenPointer == transient && seenCount == 1);
        // Inspection resources use a small fixture descriptor in this harness;
        // production compilation separately includes the real generated header.
        clear();
        packagePresent = false;
        inspectionState = 0;
        const auto &inspection = DWWeaponInspectPackage::Package;
        CHECK(inspection.installationNameCount == 10 && inspection.fastfileBytes < 400000);
        DW_BotStyleZone_LoadFastfiles(stock, 3, 3, true);
        CHECK(nativeCalls == 1 && seenCount == 4 && seenFlags == 3 && seenServer && frees == 1 &&
              writes == 2 * inspection.installationNameCount && moves == writes && !nativeMissing);
        CHECK(equal(captured[0].name, "before") && equal(captured[1].name, inspection.zoneName) &&
              equal(captured[2].name, "common_base_mp") && equal(captured[3].name, "after"));
        CHECK(captured[1].zoneFlags == stock[1].zoneFlags && captured[1].failureMode == stock[1].failureMode &&
              captured[1].priority == stock[1].priority && captured[1].reserved == stock[1].reserved);
        const unsigned inspectWrites = writes, inspectMoves = moves;
        for (unsigned pending = 1; pending <= 4; ++pending)
        {
            inspectionState = pending;
            const unsigned pendingReads = reads;
            DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
            CHECK(seenPointer == stock && seenCount == 3 && reads == pendingReads &&
                  writes == inspectWrites && moves == inspectMoves);
        }
        // Native unload returns0: queue it again, retaining already staged bytes.
        inspectionState = 0;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 1, false);
        CHECK(seenCount == 4 && equal(captured[1].name, inspection.zoneName) &&
              writes == inspectWrites && moves == inspectMoves && frees == 2 && !nativeMissing);
        DWBotStyleFastfileInfo inspectDuplicate[] = {{"common_base_mp", 1, 2, 3, 4},
                                                     {inspection.zoneName, 5, 6, 7, 8}};
        const unsigned duplicateReads = reads;
        DW_BotStyleZone_LoadFastfiles(inspectDuplicate, 2, 15, true);
        CHECK(seenPointer == inspectDuplicate && seenCount == 2 && seenFlags == 15 && seenServer &&
              reads == duplicateReads && writes == inspectWrites);
        clear();
        inspectionState = 0;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 3, true);
        CHECK(seenCount == 5 && equal(captured[1].name, inspection.zoneName) &&
              equal(captured[2].name, package.zoneName) && equal(captured[3].name, "common_base_mp") &&
              writes == 2 * (inspection.installationNameCount + package.installationNameCount) && !nativeMissing);
        CHECK(captured[1].zoneFlags == stock[1].zoneFlags && captured[2].zoneFlags == stock[1].zoneFlags &&
              captured[1].failureMode == stock[1].failureMode && captured[1].priority == stock[1].priority &&
              captured[1].reserved == stock[1].reserved && stock[1].reserved == 0x12345678);
        clear();
        packagePresent = false;
        inspectionState = 0;
        DW_BotStyleZone_LoadFastfiles(frontend, 3, 0, false);
        CHECK(seenPointer == frontend && seenCount == 3 && !writes);
        // If installation fails after moving a modified original into recovery,
        // rollback must restore that original and keep the native request intact.
        clear();
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        copyWide(stalePath, files[0].name);
        files[0].bytes[100] ^= 0x20;
        messages = 0;
        failure = 8;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 0, false);
        retained = fileAt(stalePath);
        CHECK(seenPointer == stock && seenCount == 3 && messages == 1 &&
              backupMoves == 1 && restoreMoves == 1 && retained &&
              retained->size == package.fastfileBytes);
        for (unsigned i = 0; i < package.fastfileBytes; ++i)
            CHECK(retained->bytes[i] == (i == 100 ? uint8_t(package.fastfile[i] ^ 0x20) : package.fastfile[i]));
        for (const auto &file : files)
            CHECK(!file.exists || !containsWide(file.name, L".tmp-"));
        // The executable's published map image zone: staged with every native
        // companion, then requested before the owner-built zone.
        clear();
        mapImages = true;
        packagePresent = false;
        publishedState = 0;
        DW_BotStyleZone_LoadFastfiles(frontend, 3, 1, false);
        constexpr unsigned publishedEntries =
            sizeof(DWMapImages::InstallationNames) / sizeof(*DWMapImages::InstallationNames);
        CHECK(publishedEntries == 10 && writes == 2 * publishedEntries);
        CHECK(seenCount == 5 && equal(captured[1].name, DWMapImages::ZoneName) &&
              equal(captured[2].name, "mw120r_map_images") && equal(captured[3].name, "ui"));
        CHECK(captured[1].zoneFlags == 0x40 && captured[1].failureMode == 9);
        // Loaded or pending: not requested again; staging is not repeated.
        publishedState = 2;
        const unsigned stagedWrites = writes;
        DW_BotStyleZone_LoadFastfiles(frontend, 3, 1, false);
        CHECK(seenCount == 4 && equal(captured[1].name, "mw120r_map_images") &&
              writes == stagedWrites);
        CHECK(DW_MapImages_PublishedListed(DWMapImages::MapIds[0]) &&
              !DW_MapImages_PublishedListed("mp_not_published"));
        return 0;
#undef CHECK
    }
    __declspec(dllexport) int Test_Gulag()
    {
#define CHECK(c) if (!(c)) return __LINE__
        clear();
        packagePresent = false;
        gulagState = 0;
        const auto &gulag = DWGulagNavPackage::Package;
        CHECK(sizeof(gulag) == 96 && gulag.installationNameCount == 10);
        // Preload is selected for the whole native batch, including when only
        // an unrelated row carries a preload flag. Neither case may stage the
        // ordinary-only NavMesh package or alter the original request.
        DWBotStyleFastfileInfo preload[] = {{"mp_donetsk", 0x100000, 7, 88, 0x12345678}};
        DW_BotStyleZone_LoadFastfiles(preload, 1, 2, false);
        CHECK(seenPointer == preload && seenCount == 1 && !reads && !writes && !moves);
        DWBotStyleFastfileInfo mixed[] = {{"mp_donetsk", 0x900, 7, 88, 0x12345678},
                                         {"other_preload", 0x200000, 1, 2, 3}};
        DW_BotStyleZone_LoadFastfiles(mixed, 2, 2, false);
        CHECK(seenPointer == mixed && seenCount == 2 && !reads && !writes && !moves);
        // Skipping preload must not poison staging or suppress the subsequent
        // ordinary request. A second ordinary request reuses the staged files.
        DWBotStyleFastfileInfo ordinary[] = {{"mp_donetsk", 0x900, 7, 88, 0x12345678}};
        DW_BotStyleZone_LoadFastfiles(ordinary, 1, 0, true);
        CHECK(seenCount == 2 && equal(captured[0].name, gulag.zoneName) &&
              equal(captured[1].name, "mp_donetsk") && writes == 20 && moves == 20 &&
              captured[0].zoneFlags == ordinary[0].zoneFlags &&
              captured[0].failureMode == ordinary[0].failureMode &&
              captured[0].priority == ordinary[0].priority &&
              captured[0].reserved == ordinary[0].reserved && !nativeMissing);
        DW_BotStyleZone_LoadFastfiles(ordinary, 1, 0, true);
        CHECK(seenCount == 2 && writes == 20 && moves == 20 && !nativeMissing);
        clear(); packagePresent = false; gulagState = 0;
        DWBotStyleFastfileInfo map[] = {{"before", 1, 2, 3, 4},
                                       {"mp_donetsk", 0x8008123, 7, 88, 0x12345678},
                                       {"after", 9, 10, 11, 12}};
        DW_BotStyleZone_LoadFastfiles(map, 3, 15, true);
        CHECK(nativeCalls == 1 && seenCount == 4 && seenFlags == 15 && seenServer && frees == 1);
        CHECK(equal(captured[0].name, "before") && equal(captured[1].name, gulag.zoneName) &&
              equal(captured[2].name, "mp_donetsk") && equal(captured[3].name, "after"));
        CHECK(captured[1].zoneFlags == map[1].zoneFlags && captured[1].failureMode == map[1].failureMode &&
              captured[1].priority == map[1].priority && captured[1].reserved == map[1].reserved);
        CHECK(equal(map[1].name, "mp_donetsk") && map[1].reserved == 0x12345678 &&
              writes == 20 && moves == 20 && !nativeMissing);
        const unsigned stagedWrites = writes, stagedMoves = moves;
        for (unsigned pending = 1; pending <= 4; ++pending)
        {
            gulagState = pending;
            const unsigned priorReads = reads;
            DW_BotStyleZone_LoadFastfiles(map, 3, 2, false);
            CHECK(seenPointer == map && seenCount == 3 && reads == priorReads &&
                  writes == stagedWrites && moves == stagedMoves);
        }
        gulagState = 0;
        DW_BotStyleZone_LoadFastfiles(map, 3, 2, false);
        CHECK(seenCount == 4 && equal(captured[1].name, gulag.zoneName) &&
              writes == stagedWrites && moves == stagedMoves && !nativeMissing);
        DWBotStyleFastfileInfo duplicate[] = {{gulag.zoneName, 1, 2, 3, 4},
                                             {"mp_donetsk", 5, 6, 7, 8}};
        const unsigned priorReads = reads;
        DW_BotStyleZone_LoadFastfiles(duplicate, 2, 0, false);
        CHECK(seenPointer == duplicate && seenCount == 2 && reads == priorReads);
        const char *unrelated[] = {"ui", "frontend", "common_base_mp", "mp_donetsk_tr",
                                   "mp_donetsk_extra", "mp_test", "srv_mp_donetsk"};
        for (const char *name : unrelated)
        {
            clear(); packagePresent = false; gulagState = 0;
            DWBotStyleFastfileInfo other[] = {{name, 1, 2, 3, 4}};
            DW_BotStyleZone_LoadFastfiles(other, 1, 0, false);
            CHECK(seenPointer == other && seenCount == 1 && !writes && !reads);
        }
        clear(); packagePresent = false; gulagState = 0; failure = 1;
        DW_BotStyleZone_LoadFastfiles(map, 3, 0, false);
        CHECK(seenPointer == map && seenCount == 3 && !writes);
        // All five possible overlays coexist without overwriting the input or
        // the allocation; the Gulag owner still copies the exact map record.
        clear(); gulagState = 0; inspectionState = 0; publishedState = 0; mapImages = true;
        DWBotStyleFastfileInfo combined[] = {{"common_base_mp", 0x8123, 2, 3, 4},
                                            {"mp_donetsk", 0x4567, 5, 6, 7},
                                            {"ui", 0x40, 8, 9, 10}};
        DW_BotStyleZone_LoadFastfiles(combined, 3, 3, true);
        CHECK(seenCount == 8 && seenFlags == 3 && seenServer && frees == 1 && !nativeMissing);
        unsigned gulagAt = 8;
        for (unsigned i = 0; i < seenCount; ++i)
            if (equal(captured[i].name, gulag.zoneName)) gulagAt = i;
        CHECK(gulagAt < 7 && equal(captured[gulagAt + 1].name, "mp_donetsk"));
        CHECK(captured[gulagAt].zoneFlags == combined[1].zoneFlags &&
              captured[gulagAt].failureMode == combined[1].failureMode &&
              captured[gulagAt].priority == combined[1].priority &&
              captured[gulagAt].reserved == combined[1].reserved);
        return 0;
#undef CHECK
    }
    __declspec(dllexport) int Test_CustomOperators()
    {
#define CHECK(x) do { if (!(x)) return __LINE__; } while (false)
        const auto &custom = DWCustomOperatorsPackage::Package;
        clear(); packagePresent = false; operatorsState = 0;
        DWBotStyleFastfileInfo boot[] = {{"common", 1, 4, 5, 6}, {"ui", 0x40, 7, 8, 9}};
        DW_BotStyleZone_LoadFastfiles(boot, 2, 0, false);
        CHECK(seenPointer == boot && seenCount == 2 && !writes && !operatorsInstalled);
        DWBotStyleFastfileInfo mp[] = {{"common_mp", 8, 4, 5, 6}};
        globalStreamMpState = 2;
        DW_BotStyleZone_LoadFastfiles(mp, 1, 0, false);
        CHECK(seenCount == 2 && equal(captured[0].name, "common_mp") &&
              equal(captured[1].name, custom.zoneName) && operatorsInstalled && !nativeMissing);
        CHECK(captured[1].zoneFlags == 8 && captured[1].failureMode == 4 &&
              captured[1].priority == 5 && captured[1].reserved == 6);
        CHECK(writes == 2 * custom.installationNameCount);
        unsigned previousWrites = writes;
        for (unsigned pending = 1; pending <= 4; ++pending)
        {
            operatorsState = pending;
            DW_BotStyleZone_LoadFastfiles(mp, 1, 0, false);
            CHECK(seenPointer == mp && seenCount == 1 && writes == previousWrites);
        }
        // A native unload permits a fresh request; verified files are reused.
        operatorsState = 0;
        DW_BotStyleZone_LoadFastfiles(mp, 1, 0, false);
        CHECK(seenCount == 2 && equal(captured[1].name, custom.zoneName) && writes == previousWrites);
        clear(); packagePresent = false; operatorsState = 0;
        DWBotStyleFastfileInfo ordered[] = {{"global_stream_mp", 2, 1, 2, 3},
            {"common_mp", 8, 4, 5, 6}, {"common_base_mp", 16, 7, 8, 9},
            {"common_core_mp", 32, 10, 11, 12}};
        DW_BotStyleZone_LoadFastfiles(ordered, 4, 0, false);
        CHECK(seenCount == 5 && equal(captured[4].name, custom.zoneName) &&
              equal(captured[3].name, "common_core_mp") && captured[4].zoneFlags == 8 &&
              captured[4].failureMode == 4 && captured[4].priority == 5 && captured[4].reserved == 6);
        clear(); packagePresent = false; operatorsState = 0;
        commonMpState = globalStreamMpState = 2;
        DWBotStyleFastfileInfo base[] = {{"common_base_mp", 16, 4, 5, 6}};
        DW_BotStyleZone_LoadFastfiles(base, 1, 0, false);
        CHECK(seenCount == 2 && equal(captured[1].name, custom.zoneName) && captured[1].zoneFlags == 8);
        // Queued, missing, paused and cancelled dependencies are not resident.
        for (unsigned state = 0; state <= 4; ++state)
        {
            if (state == 2) continue;
            clear(); packagePresent = false; operatorsState = 0;
            commonMpState = state; globalStreamMpState = 2;
            DW_BotStyleZone_LoadFastfiles(base, 1, 0, false);
            CHECK(seenPointer == base && seenCount == 1 && !writes);
            commonMpState = 2; globalStreamMpState = state;
            DW_BotStyleZone_LoadFastfiles(base, 1, 0, false);
            CHECK(seenPointer == base && seenCount == 1 && !writes);
        }
        clear(); packagePresent = false; operatorsState = 0;
        commonMpState = globalStreamMpState = 2;
        DWBotStyleFastfileInfo preload[] = {{"common_mp", 0x100008, 4, 5, 6}};
        DW_BotStyleZone_LoadFastfiles(preload, 1, 0, false);
        CHECK(seenPointer == preload && seenCount == 1 && !writes && !operatorsInstalled);
        DWBotStyleFastfileInfo duplicate[] = {{"common_mp", 8, 1, 2, 3}, {custom.zoneName, 8, 4, 5, 6}};
        DW_BotStyleZone_LoadFastfiles(duplicate, 2, 0, false);
        CHECK(seenPointer == duplicate && seenCount == 2 && !writes);
        clear(); packagePresent = false; operatorsState = 0; globalStreamMpState = 2; failure = 1;
        DW_BotStyleZone_LoadFastfiles(mp, 1, 0, false);
        CHECK(seenPointer == mp && seenCount == 1 && !operatorsInstalled);
        clear(); operatorsState = gulagState = inspectionState = publishedState = 0;
        globalStreamMpState = 2; mapImages = true;
        DWBotStyleFastfileInfo combined[] = {{"common_mp", 8, 1, 1, 1},
                                            {"common_base_mp", 0x8123, 2, 3, 4},
                                            {"mp_donetsk", 0x4567, 5, 6, 7},
                                            {"ui", 0x40, 8, 9, 10}};
        DW_BotStyleZone_LoadFastfiles(combined, 4, 3, true);
        CHECK(seenCount == 10 && operatorsInstalled && !nativeMissing && frees == 1);
        return 0;
#undef CHECK
    }
    __declspec(dllexport) int Test_Locale(const char *region, const char *language,
                                         const char *regionFolder, const char *languageFolder)
    {
        clear();
        regionCode = region; languageCode = language;
        regionDirectory = regionFolder; languageDirectory = languageFolder;
        DWBotStyleFastfileInfo stock[] = {{"common_base_mp", 0x8008123, 7, 88, 0}};
        DW_BotStyleZone_LoadFastfiles(stock, 1, 0, false);
        return seenCount == 2 && writes == 2 * package.installationNameCount && !nativeMissing ? 0 : 1;
    }
}
