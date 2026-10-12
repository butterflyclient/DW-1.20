// Compile the production wrapper unchanged, then model only native/OS boundaries.
#include "../integration/replay/DW_BotStyleZone.cpp"
namespace
{
struct Entry
{
    wchar_t name[1200];
    uint8_t bytes[50000];
    unsigned size, cursor;
    bool exists;
} files[128];
DWBotStyleScriptPackage package = DWBotStyleScripts::Package;
DWBotStyleFastfileInfo captured[8], allocation[8];
unsigned nativeCalls, seenCount, seenFlags, state, writes, moves, frees, messages, failure;
unsigned reads, nativeMissing;
const char *regionCode = "ww", *languageCode = "eng";
const char *regionDirectory = "worldwide", *languageDirectory = "english";
bool seenServer, packagePresent = true;
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
    package = DWBotStyleScripts::Package;
    packagePresent = true;
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
    if (failure == 4 || flags != 9)
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
    if (dest)
        dest->name[0] = 0;
    copyWide(source->name, to);
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
        return equal(name, package.zoneName) ? state : 99;
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
    void DW_BotStyleZone_LoadFastfilesNative(const DWBotStyleFastfileInfo *info, uint32_t count,
                                             uint32_t flags, bool server)
    {
        ++nativeCalls;
        seenPointer = info;
        seenCount = count;
        seenFlags = flags;
        seenServer = server;
        if (count <= 8)
            for (unsigned i = 0; i < count; ++i)
                captured[i] = info[i];
        bool overlay = false;
        for (unsigned i = 0; i < count; ++i)
            overlay |= equal(info[i].name, package.zoneName);
        if (overlay)
        {
            // Model the native consumer's actual current-locale search path.
            const char *codes[] = {regionCode, languageCode};
            for (const char *code : codes)
            {
                char name[128]{};
                unsigned at = 0;
                for (unsigned i = 0; code[i]; ++i) name[at++] = code[i];
                name[at++] = '_';
                for (unsigned i = 0; package.zoneName[i]; ++i) name[at++] = package.zoneName[i];
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
        files[0].bytes[100] ^= 0x40;
        DW_BotStyleZone_LoadFastfiles(stock, 3, 1, false);
        CHECK(seenCount == 4 && writes == oldWrites + 1);
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
