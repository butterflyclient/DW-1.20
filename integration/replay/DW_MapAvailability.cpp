#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <initializer_list>

// Complete same-build StringTable and game-info records. Data stays owned by
// the native fastfile loader; these consumers only change DW map selection.
struct DWReplayStringTable
{
    const char *name;
    int32_t columns, rows, uniqueCount;
    uint32_t reserved;
    const uint16_t *indices;
    const uint32_t *hashes;
    const char *const *strings;
};
static_assert(sizeof(DWReplayStringTable) == 48);
static_assert(offsetof(DWReplayStringTable, indices) == 24);
static_assert(offsetof(DWReplayStringTable, strings) == 40);

struct DWReplayGameTypeInfo
{
    char name[12];
    uint8_t native[160];
};
struct DWReplayMapInfo
{
    char displayName[32], loadName[16], description[32], image[32];
    uint8_t native[96];
    char gameTypes[1024];
    uint32_t supportsAliens, mapPack;
};
struct DWReplayGameInfo
{
    uint32_t gameTypeCount;
    DWReplayGameTypeInfo gameTypes[32];
    uint32_t mapCount;
    DWReplayMapInfo maps[128];
};
static_assert(sizeof(DWReplayGameTypeInfo) == 172);
static_assert(sizeof(DWReplayMapInfo) == 1240);
static_assert(offsetof(DWReplayMapInfo, gameTypes) == 208);
static_assert(offsetof(DWReplayGameInfo, maps) == 5512);

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    unsigned char Com_GameMode_GetActiveGameMode();
    int func_1413E2FE0(const DWReplayStringTable *, int column, const char *value);
    void func_1412B0570(int channel, const char *, ...);
    unsigned UI_GetMapIdForNum(unsigned index);
    DWReplayMapInfo *Com_GameInfo_GetMapInfoForIndex(unsigned index);
    extern DWReplayGameInfo gl_14C4FC330;
    extern const char *gl_145CC7538; // Native registered collision map name.
    extern int gl_145CC7534;        // Native CL_TRANSIENTS_COLLISION_MP mode.
    __declspec(dllimport) unsigned long __stdcall GetFileAttributesW(const wchar_t *);
    __declspec(dllimport) unsigned long __stdcall GetLastError();

    // Custom map packages. All callees are native Replay routines.
    void func_1410C7E70();                // Com_GameInfo_LoadMapInfoList
    void func_1410C7BB0();                // Com_GameInfo_LoadGameTypesList
    unsigned func_1413FFC30();            // Sys_GetPhysicalSectorSize
    intptr_t func_1413FAAE0(const char *, unsigned long, unsigned long, void *, unsigned long,
                            unsigned long, void *); // Sys_CreateFile (UTF-8 path)
    void func_1412B0770(int channel, const char *, ...); // Com_PrintWarning
    void func_1412B0820(int channel, const char *, ...); // Com_Printf
    __declspec(dllimport) void *__stdcall CreateFileW(const wchar_t *, unsigned long, unsigned long,
                                                      void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall ReadFile(void *, void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) void *__stdcall FindFirstFileW(const wchar_t *, void *);
    __declspec(dllimport) int __stdcall FindNextFileW(void *, void *);
    __declspec(dllimport) int __stdcall FindClose(void *);
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameW(void *, wchar_t *, unsigned long);
    __declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned, unsigned long, const wchar_t *, int,
                                                            char *, int, const char *, int *);
    __declspec(dllimport) int __stdcall VirtualProtect(void *, size_t, unsigned long, unsigned long *);

    // Ladder rung spacing. Replay climbs in rungs of 12: BG_GetLadderInfo
    // stores 12.0 as LadderInfo.rungDistance (+0x40) with an immediate, and the
    // client climb animation takes its rung parameter (0x10) from a pooled 12.0.
    void func_140CC4470(); // BG_GetLadderInfo
    void func_1416C6210(); // CG ladder climb-animation parameters
    // DW_BotStyleZone.cpp: a published map's images ship in the executable's
    // own dw_map_images zone (prepare-map-images-package.py).
    bool DW_MapImages_PublishedListed(const char *id);
}

struct DWFindData // WIN32_FIND_DATAW
{
    unsigned long attributes, times[6], sizeHigh, sizeLow, reserved[2];
    wchar_t name[260], alternate[14];
};
static_assert(sizeof(DWFindData) == 592);


namespace
{
    bool Equal(const char *left, const char *right)
    {
        if (!left || !right)
            return false;
        for (;; ++left, ++right)
        {
            const auto a = *left >= 'A' && *left <= 'Z' ? *left + 32 : *left;
            const auto b = *right >= 'A' && *right <= 'Z' ? *right + 32 : *right;
            if (a != b)
                return false;
            if (!a)
                return true;
        }
    }

    // <game>\mods\mw120r\maps\<id>\ holds exactly the five Replay zones written
    // by iw8-zonetool (<id>, srv_, eng_, ww_, techsets_) and an optional map.json.
    // Packages are scanned once by Com_GameInfo_Init, before any zone can load.
    // A map listed in mods\mw120r\map_images.txt draws loading_<id>_bg, a material
    // of the always-loaded zone\mw120r_map_images.ff, in the lobby and while loading.
    struct CustomMap
    {
        char id[16], title[64], compass[32], loading[32];
        wchar_t directory[260];
        float ladderRungDistance; // map.json "ladderRungDistance"; 12 by default
    };
    constexpr unsigned kMaxCustomMaps = 64;
    CustomMap s_customMaps[kMaxCustomMaps];
    unsigned s_customMapCount;
    // " id1 id2 ... " of the installed packages, for frontend Lua
    // (replay_dw_customMaps): a playlist of a missing map is hidden.
    char s_installedIds[kMaxCustomMaps * 16 + 2] = " ";
    const char *const kZonePrefixes[] = {"", "srv_", "eng_", "ww_", "techsets_"};

    unsigned Length(const char *text)
    {
        unsigned length = 0;
        while (text[length])
            ++length;
        return length;
    }

    void Copy(char *out, unsigned capacity, const char *first, const char *second = "")
    {
        unsigned used = 0;
        for (const char *part : {first, second})
            for (; *part && used + 1 < capacity; ++part)
                out[used++] = *part;
        out[used] = 0;
    }

    bool AppendWide(wchar_t *out, unsigned &used, unsigned capacity, const wchar_t *text)
    {
        for (; *text; ++text)
        {
            if (used + 1 >= capacity)
                return false;
            out[used++] = *text;
        }
        out[used] = 0;
        return true;
    }

    bool AppendNarrow(wchar_t *out, unsigned &used, unsigned capacity, const char *text)
    {
        for (; *text; ++text)
        {
            if (used + 1 >= capacity)
                return false;
            out[used++] = static_cast<unsigned char>(*text);
        }
        out[used] = 0;
        return true;
    }

    bool MapId(const wchar_t *name, char (&id)[16])
    {
        unsigned length = 0;
        for (; name[length]; ++length)
        {
            const auto c = name[length];
            if (length >= 15 || !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
                return false;
            id[length] = static_cast<char>(c);
        }
        id[length] = 0;
        return length > 3 && id[0] == 'm' && id[1] == 'p' && id[2] == '_';
    }

    void *OpenRead(const wchar_t *path)
    {
        constexpr unsigned long genericRead = 0x80000000UL, shareRead = 1, openExisting = 3;
        return CreateFileW(path, genericRead, shareRead, nullptr, openExisting, 0, nullptr);
    }

    // The executable's directory followed by a relative path.
    bool GamePath(wchar_t (&path)[260], const wchar_t *relative)
    {
        const auto length = GetModuleFileNameW(nullptr, path, 260);
        if (!length || length >= 260)
            return false;
        unsigned used = length;
        while (used && path[used - 1] != '\\')
            --used;
        path[used] = 0;
        return AppendWide(path, used, 260, relative);
    }

    bool MapImageZoneInstalled()
    {
        wchar_t path[260];
        return GamePath(path, L"zone\\mw120r_map_images.ff") &&
            GetFileAttributesW(path) != 0xffffffffUL;
    }

    // mods\mw120r\map_images.txt, written with the image zone: one map id per line.
    bool MapImageListed(const char *id)
    {
        static char text[8192 + 1];
        static int state; // 0 unread, 1 read, -1 absent
        if (!state)
        {
            state = -1;
            wchar_t path[260];
            if (GamePath(path, L"mods\\mw120r\\map_images.txt"))
            {
                auto *file = OpenRead(path);
                if (file != reinterpret_cast<void *>(-1))
                {
                    unsigned long read = 0;
                    if (ReadFile(file, text, sizeof(text) - 1, &read, nullptr))
                    {
                        text[read] = 0;
                        state = 1;
                    }
                    CloseHandle(file);
                }
            }
        }
        if (state != 1)
            return false;
        const auto length = Length(id);
        for (const char *line = text; *line;)
        {
            unsigned size = 0;
            while (line[size] && line[size] != '\r' && line[size] != '\n')
                ++size;
            if (size == length && !memcmp(line, id, length))
                return true;
            line += size;
            while (*line == '\r' || *line == '\n')
                ++line;
        }
        return false;
    }

    // Stored or compressed Replay 1.20 zone: header version 11, XFile 0xFF7.
    bool ReplayZone(const wchar_t *path)
    {
        auto *file = OpenRead(path);
        if (file == reinterpret_cast<void *>(-1))
            return false;
        uint8_t header[16]{};
        unsigned long read = 0;
        const bool ok = ReadFile(file, header, sizeof(header), &read, nullptr) && read == sizeof(header);
        CloseHandle(file);
        uint32_t version = 0, xfile = 0;
        memcpy(&version, header + 8, 4);
        memcpy(&xfile, header + 12, 4);
        return ok && (!memcmp(header, "IWffc100", 8) || !memcmp(header, "IWffa100", 8)) &&
            version == 11 && xfile == 0xFF7;
    }

    // Reads "title" (or its alias "name") from map.json; other keys are ignored.
    void ReadTitle(const wchar_t *path, char (&title)[64])
    {
        auto *file = OpenRead(path);
        if (file == reinterpret_cast<void *>(-1))
            return;
        static char text[4096 + 8]; // key compares may read past the terminator
        unsigned long read = 0;
        ReadFile(file, text, 4095, &read, nullptr);
        CloseHandle(file);
        text[read] = 0;
        for (const char *key : {"\"title\"", "\"name\""})
        {
            const auto keyLength = Length(key);
            const char *at = text;
            while (*at && memcmp(at, key, keyLength))
                ++at;
            if (!*at)
                continue;
            at += keyLength;
            while (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n' || *at == ':')
                ++at;
            if (*at++ != '"')
                continue;
            unsigned used = 0;
            for (; *at && *at != '"' && used + 1 < sizeof(title); ++at)
                if (*at != '\\')
                    title[used++] = *at;
            if (used)
            {
                title[used] = 0;
                return;
            }
        }
    }

    // Reads "ladderRungDistance" from map.json: the rung spacing of a converted
    // map's original ladder models (iw8-zonetool), 8 to 32 units; 12 otherwise.
    float ReadLadderRungDistance(const wchar_t *path)
    {
        auto *file = OpenRead(path);
        if (file == reinterpret_cast<void *>(-1))
            return 12.0f;
        static char text[4096 + 8];
        unsigned long read = 0;
        ReadFile(file, text, 4095, &read, nullptr);
        CloseHandle(file);
        text[read] = 0;
        const char key[] = "\"ladderRungDistance\"";
        const char *at = text;
        while (*at && memcmp(at, key, sizeof(key) - 1))
            ++at;
        if (!*at)
            return 12.0f;
        at += sizeof(key) - 1;
        while (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n' || *at == ':')
            ++at;
        float value = 0, scale = 0;
        for (; (*at >= '0' && *at <= '9') || (*at == '.' && !scale); ++at)
        {
            if (*at == '.')
                scale = 1;
            else if (scale)
                value += (*at - '0') * (scale *= 0.1f);
            else
                value = value * 10 + (*at - '0');
        }
        return value >= 8.0f && value <= 32.0f ? value : 12.0f;
    }

    // Applied when a map's main zone opens. Each site is checked against its
    // exact native encoding before it is written; a mismatch leaves Replay's 12.
    float s_ladderRungDistance = 12.0f;

    bool WriteCode(uint8_t *at, const void *bytes, size_t size)
    {
        unsigned long protection = 0;
        if (!VirtualProtect(at, size, 0x40, &protection)) // PAGE_EXECUTE_READWRITE
            return false;
        memcpy(at, bytes, size);
        // x64 keeps instruction fetch coherent with these writes; the sites
        // do not run while a map zone opens.
        VirtualProtect(at, size, protection, &protection);
        return true;
    }

    void ApplyLadderRungDistance(float distance)
    {
        static bool redirected, warned;
        // BG_GetLadderInfo +0x101: mov dword ptr [r14+40h], imm32 (12.0 natively).
        auto *store = reinterpret_cast<uint8_t *>(&func_140CC4470) + 0x101;
        static const uint8_t storeOpcode[4] = {0x41, 0xC7, 0x46, 0x40};
        // Climb parameters +0x3AB: movss xmm2, dword ptr [rip+disp32] (the pooled 12.0).
        auto *load = reinterpret_cast<uint8_t *>(&func_1416C6210) + 0x3AB;
        static const uint8_t loadOpcode[4] = {0xF3, 0x0F, 0x10, 0x15};
        bool ok = !memcmp(store, storeOpcode, sizeof(storeOpcode)) && !memcmp(load, loadOpcode, sizeof(loadOpcode));
        if (ok && !redirected)
        {
            const intptr_t delta = reinterpret_cast<intptr_t>(&s_ladderRungDistance) -
                reinterpret_cast<intptr_t>(load + 8);
            const int32_t displacement = static_cast<int32_t>(delta);
            ok = displacement == delta && WriteCode(load + 4, &displacement, sizeof(displacement));
            redirected = ok;
        }
        if (!ok)
        {
            if (!warned)
                func_1412B0770(16, "[DW] ladder rung spacing unchanged: native ladder code differs\n");
            warned = true;
            return;
        }
        uint32_t current = 0, wanted = 0;
        memcpy(&current, store + 4, 4);
        memcpy(&wanted, &distance, 4);
        if (current != wanted)
            WriteCode(store + 4, &wanted, 4);
        s_ladderRungDistance = distance;
    }

    void ScanCustomMaps()
    {
        s_customMapCount = 0;
        Copy(s_installedIds, sizeof(s_installedIds), " ");
        wchar_t root[260];
        const auto length = GetModuleFileNameW(nullptr, root, 260);
        if (!length || length >= 260)
            return;
        unsigned rootLength = length;
        while (rootLength && root[rootLength - 1] != '\\')
            --rootLength;
        root[rootLength] = 0;

        wchar_t pattern[260];
        unsigned used = 0;
        if (!AppendWide(pattern, used, 260, root) ||
            !AppendWide(pattern, used, 260, L"mods\\mw120r\\maps\\*"))
            return;
        DWFindData found{};
        auto *search = FindFirstFileW(pattern, &found);
        if (search == reinterpret_cast<void *>(-1))
            return;
        do
        {
            CustomMap &map = s_customMaps[s_customMapCount];
            if (!(found.attributes & 0x10) || (found.attributes & 0x400) || !MapId(found.name, map.id))
                continue;
            wchar_t path[260];
            unsigned directoryLength = 0, pathLength = 0;
            // A stock map of the same name always wins.
            if (!AppendWide(path, pathLength, 260, root) || !AppendWide(path, pathLength, 260, L"zone\\") ||
                !AppendNarrow(path, pathLength, 260, map.id) || !AppendWide(path, pathLength, 260, L".ff") ||
                GetFileAttributesW(path) != 0xffffffffUL)
                continue;
            if (!AppendWide(map.directory, directoryLength, 260, root) ||
                !AppendWide(map.directory, directoryLength, 260, L"mods\\mw120r\\maps\\") ||
                !AppendWide(map.directory, directoryLength, 260, found.name) ||
                !AppendWide(map.directory, directoryLength, 260, L"\\"))
                continue;
            bool complete = true;
            for (const char *prefix : kZonePrefixes)
            {
                pathLength = 0;
                complete = complete && AppendWide(path, pathLength, 260, map.directory) &&
                    AppendNarrow(path, pathLength, 260, prefix) &&
                    AppendNarrow(path, pathLength, 260, map.id) &&
                    AppendWide(path, pathLength, 260, L".ff") && ReplayZone(path);
            }
            if (!complete)
            {
                func_1412B0770(16, "[DW] custom map %s skipped: missing or invalid Replay zone\n", map.id);
                continue;
            }
            Copy(map.title, sizeof(map.title), map.id);
            pathLength = 0;
            if (AppendWide(path, pathLength, 260, map.directory) &&
                AppendWide(path, pathLength, 260, L"map.json"))
            {
                ReadTitle(path, map.title);
                map.ladderRungDistance = ReadLadderRungDistance(path);
            }
            else
                map.ladderRungDistance = 12.0f;
            Copy(map.compass, sizeof(map.compass), "compass_map_", map.id);
            map.loading[0] = 0;
            if ((MapImageZoneInstalled() && MapImageListed(map.id)) ||
                DW_MapImages_PublishedListed(map.id))
            {
                Copy(map.loading, sizeof(map.loading), "loading_", map.id);
                const auto used = Length(map.loading);
                Copy(map.loading + used, sizeof(map.loading) - used, "_bg");
            }
            func_1412B0820(16, "[DW] custom map %s (%s) available%s%s\n", map.id, map.title,
                           map.loading[0] ? ", loading image " : "", map.loading);
            {
                const auto installed = Length(s_installedIds);
                Copy(s_installedIds + installed, sizeof(s_installedIds) - installed, map.id, " ");
            }
            ++s_customMapCount;
        } while (s_customMapCount < kMaxCustomMaps && FindNextFileW(search, &found));
        FindClose(search);
    }

    const CustomMap *FindCustomMap(const char *id)
    {
        for (unsigned i = 0; id && i < s_customMapCount; ++i)
            if (Equal(s_customMaps[i].id, id))
                return &s_customMaps[i];
        return nullptr;
    }

    // Native zone requests name only the file; route a package's five zones
    // to its folder and leave every other request untouched.
    bool CustomZonePath(const char *request, char *out, int capacity)
    {
        const char *name = request;
        for (const char *at = request; *at; ++at)
            if (*at == '\\' || *at == '/')
                name = at + 1;
        for (unsigned i = 0; i < s_customMapCount; ++i)
            for (const char *prefix : kZonePrefixes)
            {
                char zone[48];
                Copy(zone, sizeof(zone), prefix, s_customMaps[i].id);
                Copy(zone + Length(zone), sizeof(zone) - Length(zone), ".ff");
                if (!Equal(name, zone))
                    continue;
                wchar_t path[260];
                unsigned used = 0;
                return AppendWide(path, used, 260, s_customMaps[i].directory) &&
                    AppendNarrow(path, used, 260, zone) &&
                    WideCharToMultiByte(65001, 0, path, -1, out, capacity, nullptr, nullptr) > 0;
            }
        return false;
    }

    // zone\<loadName>.ff exists: a stock map this build can load.
    bool StockZoneInstalled(const char *loadName)
    {
        wchar_t path[260];
        const auto length = GetModuleFileNameW(nullptr, path, 260);
        if (!length || length >= 260)
            return true;
        unsigned used = length;
        while (used && path[used - 1] != '\\')
            --used;
        path[used] = 0;
        return !AppendWide(path, used, 260, L"zone\\") || !AppendNarrow(path, used, 260, loadName) ||
            !AppendWide(path, used, 260, L".ff") || GetFileAttributesW(path) != 0xffffffffUL;
    }

    void AppendCustomMaps()
    {
        ScanCustomMaps();
        auto &info = gl_14C4FC330;
        if (info.mapCount > 128)
            return;
        const DWReplayMapInfo *reference = nullptr;
        for (unsigned i = 0; i < info.mapCount && !reference; ++i)
            if (Equal(info.maps[i].loadName, "mp_shipment"))
                reference = &info.maps[i];
        if (!reference)
        {
            func_1412B0770(16, "[DW] native map list has no Shipment template; custom maps not listed\n");
            return;
        }
        const DWReplayMapInfo shipment = *reference;
        // Replay 1.20's mp/basemaps.arena lists 115 of the table's 128 rows, so
        // only 13 packages fit after it. In multiplayer, packages also take the
        // rows of co-op maps (cp_*) whose zones this build does not install.
        bool customRow[128]{};
        const bool multiplayer = Com_GameMode_GetActiveGameMode() == 2;
        for (unsigned i = 0; i < s_customMapCount; ++i)
        {
            const auto &map = s_customMaps[i];
            unsigned index = info.mapCount;
            // A package beats a stock row of the same name whose zone is not
            // installed (ScanCustomMaps already lets an installed stock map win).
            for (unsigned j = 0; j < info.mapCount && index == info.mapCount; ++j)
                if (Equal(info.maps[j].loadName, map.id))
                    index = j;
            if (index == info.mapCount && info.mapCount == 128)
                for (unsigned j = 0; multiplayer && j < info.mapCount && index == info.mapCount; ++j)
                {
                    const char *name = info.maps[j].loadName;
                    if (!customRow[j] && name[0] == 'c' && name[1] == 'p' && name[2] == '_' &&
                        !StockZoneInstalled(name))
                        index = j;
                }
            if (index >= 128)
            {
                func_1412B0770(16, "[DW] custom map %s not listed: the map table is full\n", map.id);
                continue;
            }
            if (index == info.mapCount)
                ++info.mapCount;
            else if (!customRow[index])
                func_1412B0820(16, "[DW] custom map %s listed in place of uninstalled %s\n", map.id,
                               info.maps[index].loadName);
            customRow[index] = true;
            // Shipment's native presentation, ownership and rules; the converted
            // packages carry Team Deathmatch spawns only.
            auto &row = info.maps[index];
            memcpy(&row, &shipment, sizeof(row));
            Copy(row.displayName, sizeof(row.displayName), "\x1f", map.title);
            Copy(row.loadName, sizeof(row.loadName), map.id);
            Copy(row.description, sizeof(row.description), "\x1f" "Custom map");
            Copy(reinterpret_cast<char *>(row.native + 0x40), 32, "war");
            Copy(row.gameTypes, sizeof(row.gameTypes), "war");
            if (map.loading[0]) // the lobby's map image (arena "mapimage")
                Copy(row.image, sizeof(row.image), map.loading);
            row.supportsAliens = 0;
        }
    }

    // mp/mapInfo.csv has no rows for custom maps. Answer the presentation
    // columns the frontend reads; everything else follows Shipment's row.
    const char *CustomMapInfo(const DWReplayStringTable *table, const char *value, int resultColumn);
}

// Mode 2 requests the combined <map>_cg_ls_tr package. Replay's Verdansk
// package set supplies numbered collision tiles instead. Use the existing
// mode-1 tile scheduler when the combined file is genuinely absent; keep its
// memory budget, priorities, physics setup and unload lifecycle native.
extern "C" void CL_TransientsCollisionMP_SetTransientMode(int mode)
{
    if (mode == 2 && DW_LocalBackend_IsEnabled() &&
        Equal(gl_145CC7538, "mp_donetsk"))
    {
        const auto combined = GetFileAttributesW(L"zone\\mp_donetsk_cg_ls_tr.ff");
        const auto error = combined == 0xffffffffUL ? GetLastError() : 0UL;
        if (combined == 0xffffffffUL && (error == 2 || error == 3))
        {
            const auto tile = GetFileAttributesW(L"zone\\mp_donetsk_cg_00000_tr.ff");
            if (tile != 0xffffffffUL && !(tile & 0x10UL))
            {
                mode = 1;
                func_1412B0570(16, "[DW] Verdansk collision: numbered transient tiles; combined cg_ls_tr package absent\n");
            }
        }
    }
    gl_145CC7534 = mode;
}


// Original lookup searches from the last row and uses the exact native hash
// and case-insensitive comparator. Reuse that row selector for all tables.
extern "C" const char *func_1413E2BA0(const DWReplayStringTable *table,
                                     int column, const char *value, int resultColumn)
{
    if (!table)
    {
        func_1412B0570(13, "Unable to find the lookup table in the fastfile, aborting lookup\n");
        return "";
    }
    if (!table->columns || column < 0 || resultColumn < 0 || resultColumn >= table->columns)
        return "";
    // An installed package answers its own presentation columns, also when
    // mp/mapInfo.csv has a row for an uninstalled stock map of the same name.
    if (column == 0)
        if (const auto *custom = CustomMapInfo(table, value, resultColumn))
            return custom;
    const auto row = func_1413E2FE0(table, column, value);
    if (row < 0 || row >= table->rows)
        return "";
    const auto cell = table->indices[row * table->columns + resultColumn];
    if (cell >= table->uniqueCount)
        return "";
    if (DW_LocalBackend_IsEnabled() && column == 0 && resultColumn == 28 &&
        Equal(table->name, "mp/mapInfo.csv") && Equal(value, "mp_donetsk"))
        return "0"; // Native PRIVATE_MATCH.MapSupportsCustomGames uses this column.
    return table->strings[cell];
}

extern "C" const char *func_141B9D400(unsigned index)
{
    const auto mapIndex = UI_GetMapIdForNum(index);
    const auto *map = Com_GameInfo_GetMapInfoForIndex(mapIndex);
    if (!DW_LocalBackend_IsEnabled() || Com_GameMode_GetActiveGameMode() != 2 ||
        !Equal(map->loadName, "mp_donetsk"))
        return map->gameTypes;

    // The same MP selector is used by local and online custom games. Offer
    // only game types that this native game-info publication actually loaded.
    // Copy no server/weapon rules or map assets, and keep BR arena rules intact.
    static char supported[1024];
    unsigned used = 0;
    const auto count = gl_14C4FC330.gameTypeCount;
    if (count > 32)
        return map->gameTypes;
    for (unsigned i = 0; i < count; ++i)
    {
        const auto *name = gl_14C4FC330.gameTypes[i].name;
        unsigned length = 0;
        while (length < sizeof(gl_14C4FC330.gameTypes[i].name) && name[length])
            ++length;
        if (!length || length == sizeof(gl_14C4FC330.gameTypes[i].name))
            continue;
        if (used && used + 1 < sizeof(supported))
            supported[used++] = ' ';
        for (unsigned j = 0; j < length && used + 1 < sizeof(supported); ++j)
            supported[used++] = name[j];
    }
    supported[used] = 0;
    return used ? supported : map->gameTypes;
}

namespace
{
    const char *CustomMapInfo(const DWReplayStringTable *table, const char *value, int resultColumn)
    {
        const auto *map = FindCustomMap(value);
        if (!map || !Equal(table->name, "mp/mapInfo.csv"))
            return nullptr;
        switch (resultColumn)
        {
        case 1:  // name
        case 2:  // caps
        case 24: // baseName
            return map->title;
        case 3: // isNightMap
            return "0";
        case 18: // arenaMenuMinimap: the package's own compass image
            return map->compass;
        case 22: // loading screen image
            if (map->loading[0])
                return map->loading;
            return func_1413E2BA0(table, 0, "mp_shipment", resultColumn);
        case 28: // hideInMapSelect: offered by PRIVATE_MATCH.MapSupportsCustomGames
            return "0";
        default:
            return func_1413E2BA0(table, 0, "mp_shipment", resultColumn);
        }
    }
}

// DW_BotStyleZone.cpp loads the image zone with the common zones when installed.
// The first DW frame runs before Com_GameInfo_Init's scan (logged 2026-10-16:
// an empty list at the first frame, the full one later), and the frontend
// playlist buttons are built in between. Scanning here first lets the
// required-map guard see the installed packages; Com_GameInfo_Init rescans.
extern "C" void DW_MapAvailability_EnsureScanned()
{
    static bool s_scanned;
    if (s_scanned || s_customMapCount)
        return;
    s_scanned = true;
    ScanCustomMaps();
}

extern "C" const char *DW_MapAvailability_InstalledIds()
{
    return s_installedIds;
}

extern "C" bool DW_MapImages_ZoneInstalled()
{
    return MapImageZoneInstalled();
}

// Native 0x10C78D0: load the stock map list, publish installed custom map
// packages beside it, then load game types exactly as before.
extern "C" void func_1410C78D0()
{
    func_1410C7E70();
    AppendCustomMaps();
    func_1410C7BB0();
}

// Native 0x13F4D50 Sys_OpenFileReliable, with custom package zones routed to
// their folder. Handle ownership, flags and error reporting stay native.
extern "C" intptr_t func_1413F4D50(const char *name, unsigned flags)
{
    unsigned long attributes = static_cast<unsigned long>(flags & 8) << 27;
    if (flags & 0x10)
    {
        const auto sector = func_1413FFC30();
        if (!sector)
            func_1412B0770(10, "Sys_OpenFileReliable: the physical sector size of the disk is unknown and FILE_FLAG_NO_BUFFERING cannot be used for \"%s\".\n", name);
        else if (sector > 0x1000)
            func_1412B0770(10, "Sys_OpenFileReliable: the physical sector size(%d) of the disk is bigger than the data alignment(%d) and FILE_FLAG_NO_BUFFERING cannot be used for \"%s\".\n", sector, 4096, name);
        else
            attributes |= 0x20000000UL;
    }
    char custom[1024];
    const char *path = s_customMapCount && CustomZonePath(name, custom, sizeof(custom)) ? custom : name;
    // A map's main zone (<map>.ff, no srv_/eng_/ww_/techsets_ prefix) selects
    // its ladder rung spacing: a custom package's own, Replay's 12 otherwise.
    {
        const char *file = name;
        for (const char *at = name; *at; ++at)
            if (*at == '\\' || *at == '/')
                file = at + 1;
        if (file[0] == 'm' && file[1] == 'p' && file[2] == '_')
        {
            float distance = 12.0f;
            for (unsigned i = 0; i < s_customMapCount; ++i)
            {
                char zone[48];
                Copy(zone, sizeof(zone), s_customMaps[i].id, ".ff");
                if (Equal(file, zone))
                    distance = s_customMaps[i].ladderRungDistance;
            }
            const auto length = Length(file);
            if (length > 3 && Equal(file + length - 3, ".ff"))
                ApplyLadderRungDistance(distance);
        }
    }
    const auto result = func_1413FAAE0(path, 0x80000000UL, 1, nullptr, 3, attributes, nullptr);
    if (result != -1)
        return result;
    const auto error = GetLastError();
    if (error == 2 || error == 3)
        return -1;
    if (error == 5)
        func_1412B0820(10, "Sys_OpenFileReliable: Access denied opening file %s\n", path);
    else
        func_1412B0820(10, "Sys_OpenFileReliable: Unknown Error %x for file %s\n", error, path);
    return -1;
}
