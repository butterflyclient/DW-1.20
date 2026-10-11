#include "DW_LocalConfig.h"
#include "dw_unlock_progression_caps.h"
#include <stddef.h>
#include <stdint.h>

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void *func_14105BC30();
    int func_1420838B0(void *);
    int func_1420839E0(void *, int);
    int func_142083A30(void *, int);
    int func_1419CE9B0(void *, int);
    const char *func_142084950(void *, int, size_t *);
    void func_142084100(void *, double);
    void func_1420833B0(void *, int, int);
    void func_1419CE4F0(const char *, uint64_t, void *);
    int func_142089FB0(void *, const char *, ...);
    int func_140D66C20(int);
    extern uint8_t gl_14414CC80[];
    extern uint64_t gl_1444879C8[];
}

namespace
{
    struct WeaponProgression
    {
        const char *reference;
        uint64_t achievement, xp, rank;
    };
    struct GunsmithClient
    {
        WeaponProgression weapons[64];
        int32_t count;
        uint32_t padding;
    };
    struct GunsmithPrefix
    {
        uint8_t native[64];
        GunsmithClient clients[2];
    };
    static_assert(sizeof(WeaponProgression) == 32);
    static_assert(sizeof(GunsmithClient) == 2056);
    static_assert(offsetof(GunsmithPrefix, clients) == 64);
    static_assert(offsetof(GunsmithPrefix, clients) + offsetof(GunsmithClient, count) == 2112);
    static_assert(offsetof(GunsmithPrefix, clients) + sizeof(GunsmithClient) +
                  offsetof(GunsmithClient, count) == 4168);

    bool ProjectMaximum()
    {
        return DW_LocalBackend_IsEnabled() && DW_LocalConfig_UnlockAll();
    }

    bool EqualReference(const char *left, const char *right)
    {
        if (!left || !right)
            return false;
        for (;; ++left, ++right)
        {
            unsigned a = static_cast<unsigned char>(*left);
            unsigned b = static_cast<unsigned char>(*right);
            if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
            if (a != b) return false;
            if (!a) return true;
        }
    }

    int PlayerValue(void *vm, bool seasonValue, bool rankValue)
    {
        const int arguments = seasonValue ? 2 : 1;
        if (func_1420838B0(vm) != arguments || !func_1420839E0(vm, 1) ||
            (seasonValue && !func_1420839E0(vm, 2)))
            return func_142089FB0(vm, "Invalid OnlineProgression getter arguments");
        const int controller = func_1419CE9B0(vm, 1);
        const int season = seasonValue ? func_1419CE9B0(vm, 2) : 0;
        if (controller < 0 || controller >= 8 || season < 0 || season >= 7)
            return func_142089FB0(vm, "Invalid OnlineProgression getter index");
        const auto *native = static_cast<const uint8_t *>(func_14105BC30());
        const size_t offset = seasonValue ? 80 + 16 * (7 * controller + season)
                                          : 64 + 16 * controller;
        uint64_t value = *reinterpret_cast<const uint64_t *>(native + offset + (rankValue ? 8 : 0));
        if (ProjectMaximum())
            value = rankValue ? (seasonValue ? 99 : 54)
                              : (seasonValue ? dwReplayMaximumSeasonXp[season]
                                             : dwReplayMaximumPlayerXp);
        func_142084100(vm, static_cast<double>(value));
        if (func_1420838B0(vm) < 1)
            return func_142089FB0(vm, "OnlineProgression return stack mismatch");
        return 1;
    }
}

// Exact same-Replay OnlineProgression registration targets. Projection changes
// only returned Lua values; earned progression and its persistence remain native.
extern "C" int func_1410592B0(void *vm) { return PlayerValue(vm, false, false); }
extern "C" int func_141059360(void *vm) { return PlayerValue(vm, false, true); }
extern "C" int func_141059410(void *vm) { return PlayerValue(vm, true, false); }
extern "C" int func_141059500(void *vm) { return PlayerValue(vm, true, true); }

// GetPlayerLevel combines this lifetime offset with the season-0 rank. Its
// projected maximum is level 155, independently of real historical season XP.
extern "C" int func_141059A80(void *vm)
{
    if (func_1420838B0(vm) != 1 || !func_1420839E0(vm, 1))
        return func_142089FB0(vm, "Invalid OnlineProgression level arguments");
    const int controller = func_1419CE9B0(vm, 1);
    if (controller < 0 || controller >= 8)
        return func_142089FB0(vm, "Invalid OnlineProgression controller");
    const auto value = ProjectMaximum() ? uint64_t{0} : gl_1444879C8[2 * controller];
    func_142084100(vm, static_cast<double>(value));
    if (func_1420838B0(vm) < 1)
        return func_142089FB0(vm, "OnlineProgression return stack mismatch");
    return 1;
}

// Native Gunsmith.BEDFIJHAB helper returns one table containing xp and rank.
extern "C" int func_140F58C60(void *vm)
{
    if (func_1420838B0(vm) != 2 || !func_1420839E0(vm, 1) || !func_142083A30(vm, 2))
        return func_142089FB0(vm, "Invalid Gunsmith.GetWeaponInfo arguments");
    const int controller = func_1419CE9B0(vm, 1);
    const char *reference = func_142084950(vm, 2, nullptr);
    const int client = func_140D66C20(controller);
    uint64_t xp = 0, rank = 0;
    if (client >= 0 && client < 2)
    {
        const auto &native = reinterpret_cast<const GunsmithPrefix *>(gl_14414CC80)->clients[client];
        if (native.count >= 0 && native.count <= 64)
            for (int index = 0; index < native.count; ++index)
                if (EqualReference(native.weapons[index].reference, reference))
                {
                    xp = native.weapons[index].xp;
                    rank = native.weapons[index].rank;
                    break;
                }
        if (ProjectMaximum())
            for (const auto &cap : dwReplayWeaponCaps)
                if (EqualReference(cap.reference, reference))
                {
                    xp = cap.xp;
                    rank = cap.rank;
                    break;
                }
    }
    func_1420833B0(vm, 0, 0);
    func_1419CE4F0("xp", xp, vm);
    func_1419CE4F0("rank", rank, vm);
    return 1;
}
