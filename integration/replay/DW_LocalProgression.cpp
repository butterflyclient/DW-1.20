#include "DW_LocalProgression.h"
#include "DW_LocalConfig.h"
#include "replay_dvar.h"
#include "dw_progression_ranks.h"
#include <stddef.h>

extern "C"
{
    uint64_t DW_LocalPlatform_UserId();
    void *func_14105BC30(); // Original OnlineProgression::GetInstance
    __declspec(dllimport) unsigned long __stdcall GetEnvironmentVariableW(
        const wchar_t *, wchar_t *, unsigned long);
    __declspec(dllimport) int __stdcall CreateDirectoryW(const wchar_t *, void *);
    __declspec(dllimport) void *__stdcall CreateFileW(
        const wchar_t *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall ReadFile(
        void *, void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) int __stdcall WriteFile(
        void *, const void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) int __stdcall FlushFileBuffers(void *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) int __stdcall MoveFileExW(const wchar_t *, const wchar_t *, unsigned long);
    __declspec(dllimport) unsigned long __stdcall GetTickCount();
    void Com_Printf(int, const char *, ...);
}

namespace
{
    struct DWLocalProgressionRecord
    {
        uint32_t magic, version;
        uint64_t user, xp;
        uint32_t appliedRank, reserved;
        uint64_t checksum;
    };
    static_assert(sizeof(DWLocalProgressionRecord) == 40);
    static_assert(offsetof(DWLocalProgressionRecord, checksum) == 32);

    // Same Replay constructor and UpdateProgression: the complete player-array
    // prefix is 64 bytes followed by eight native (XP, rank) pairs.
    struct DWReplayPlayerProgression
    {
        uint64_t xp, rank;
    };
    struct DWReplayProgressionPrefix
    {
        uint8_t native[64];
        DWReplayPlayerProgression players[8];
    };
    static_assert(offsetof(DWReplayProgressionPrefix, players) == 64);
    static_assert(sizeof(DWReplayProgressionPrefix) == 192);

    DWLocalProgressionRecord s_record{};
    uint64_t s_savedUser = 0, s_savedXp = 0;
    unsigned s_savedRank = 0, s_savedValid = 0;
    wchar_t s_directory[1024]{}, s_path[1100]{}, s_pending[1100]{};
    bool s_loaded = false, s_valid = false, s_corrupt = false;
    unsigned s_poll = 0, s_unlockMask = 0;

    uint64_t Checksum(const DWLocalProgressionRecord &record)
    {
        uint64_t value = 14695981039346656037ULL;
        const auto *bytes = reinterpret_cast<const uint8_t *>(&record);
        for (unsigned i = 0; i < offsetof(DWLocalProgressionRecord, checksum); ++i)
            value = (value ^ bytes[i]) * 1099511628211ULL;
        return value;
    }

    void Append(wchar_t *destination, const wchar_t *suffix)
    {
        while ((*destination++ = *suffix++) != 0)
        {
            // Callers provide bounded fixed suffixes after a bounded environment path.
        }
    }

    void Load()
    {
        if (s_loaded)
            return;
        s_loaded = true;
        const auto length = GetEnvironmentVariableW(L"LOCALAPPDATA", s_directory, 900);
        if (!length || length >= 900)
            return;
        Append(s_directory + length, L"\\ReplayDW");
        unsigned end = 0;
        while (s_directory[end])
        {
            s_path[end] = s_pending[end] = s_directory[end];
            ++end;
        }
        Append(s_path + end, L"\\player-progression.bin");
        Append(s_pending + end, L"\\player-progression.pending");
        auto file = CreateFileW(s_path, 0x80000000, 1, nullptr, 3, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return;
        DWLocalProgressionRecord record{};
        unsigned long received = 0, extraCount = 0;
        uint8_t extra = 0;
        const bool read = ReadFile(file, &record, sizeof(record), &received, nullptr) &&
                          received == sizeof(record) &&
                          ReadFile(file, &extra, 1, &extraCount, nullptr) && !extraCount;
        CloseHandle(file);
        s_valid = read && record.magic == 0x31505852 && record.version == 1 &&
                  record.user && record.appliedRank <= 55 && !record.reserved &&
                  record.checksum == Checksum(record);
        s_corrupt = !s_valid;
        if (s_valid)
        {
            s_record = record;
            __atomic_store_n(&s_savedUser, record.user, __ATOMIC_RELEASE);
            __atomic_store_n(&s_savedXp, record.xp, __ATOMIC_RELEASE);
            __atomic_store_n(&s_savedRank, record.appliedRank, __ATOMIC_RELEASE);
            __atomic_store_n(&s_savedValid, 1U, __ATOMIC_RELEASE);
        }
        else
            Com_Printf(25, "[DW] Local progression record invalid; preserving the existing file\n");
    }

    bool Save(uint64_t user, uint64_t xp)
    {
        if (!s_path[0] || s_corrupt)
            return false;
        CreateDirectoryW(s_directory, nullptr);
        DWLocalProgressionRecord record{0x31505852, 1, user, xp, DW_LocalConfig_Rank(), 0, 0};
        record.checksum = Checksum(record);
        auto file = CreateFileW(s_pending, 0x40000000, 0, nullptr, 2, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return false;
        unsigned long written = 0;
        const bool saved = WriteFile(file, &record, sizeof(record), &written, nullptr) &&
                           written == sizeof(record) && FlushFileBuffers(file);
        CloseHandle(file);
        if (!saved || !MoveFileExW(s_pending, s_path, 9))
            return false;
        s_record = record;
        s_valid = true;
        __atomic_store_n(&s_savedUser, record.user, __ATOMIC_RELEASE);
        __atomic_store_n(&s_savedXp, record.xp, __ATOMIC_RELEASE);
        __atomic_store_n(&s_savedRank, record.appliedRank, __ATOMIC_RELEASE);
        __atomic_store_n(&s_savedValid, 1U, __ATOMIC_RELEASE);
        Com_Printf(25, "[DW] Local player progression saved: XP %llu\n", xp);
        return true;
    }
}

extern "C" bool DW_LocalProgression_LoginFields(uint64_t *user, uint64_t *xp, unsigned *appliedRank)
{
    Load();
    const bool valid = __atomic_load_n(&s_savedValid, __ATOMIC_ACQUIRE) != 0;
    *user = valid ? __atomic_load_n(&s_savedUser, __ATOMIC_ACQUIRE) : 0;
    *xp = valid ? __atomic_load_n(&s_savedXp, __ATOMIC_ACQUIRE) : 0;
    *appliedRank = valid ? __atomic_load_n(&s_savedRank, __ATOMIC_ACQUIRE) : 0;
    return valid;
}

extern "C" void DW_LocalProgression_Frame()
{
    const auto user = DW_LocalPlatform_UserId();
    if (!user)
        return;
    const auto now = GetTickCount();
    if (now - s_poll < 250)
        return;
    s_poll = now;
    Load();
    constexpr const char *unlocks[] = {
        "unlock_all_loot", "unlockAllItems", "allEmblemsUnlocked",
        "force_unlock_all_attachments", "force_unlock_all_attachment_lines",
        "force_unlock_all_killstreaks"};
    for (unsigned i = 0; i < sizeof(unlocks) / sizeof(*unlocks); ++i)
        if (!(s_unlockMask & (1U << i)))
        {
            auto *dvar = Dvar_FindVarByName(unlocks[i]);
            if (!dvar || dvar->type != 0)
                continue;
            DvarValue value{};
            value.enabled = DW_LocalConfig_UnlockAll();
            Dvar_SetVariant(dvar, &value, 0);
            s_unlockMask |= 1U << i;
        }
    const auto *progression = static_cast<const DWReplayProgressionPrefix *>(func_14105BC30());
    if (!progression)
        return;
    const auto xp = progression->players[0].xp;
    // Native arrays are briefly reset during sign-in/reconciliation. Never
    // erase a saved earned total before its authenticated local restore arrives.
    const auto configuredRank = DW_LocalConfig_Rank();
    const bool changedRank = configuredRank &&
                             (!s_valid || s_record.appliedRank != configuredRank);
    if (changedRank && xp < dwReplayPlayerRankMinimumXp[configuredRank - 1])
        return;
    if (s_valid && (s_record.user != user ||
        (!changedRank && xp < s_record.xp) ||
        (xp == s_record.xp && s_record.appliedRank == configuredRank)))
        return;
    if (!s_valid && !xp && !configuredRank)
        return;
    Save(user, xp);
}
