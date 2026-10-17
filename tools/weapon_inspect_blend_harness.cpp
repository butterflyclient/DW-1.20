// Deferred fixture: compile this separately from the actual blend owner.
#include "DW_WeaponInspectBlend.h"
#include "DW_WeaponInspectBlendBindings.h"
#include <assert.h>
#include <stdio.h>

namespace
{
    struct Client
    {
        uint64_t unknown0;
        DWInspectPlayerState ps;
    } client{};
    static_assert(offsetof(Client, ps) == 8);
    constexpr uint64_t NativeResult = 0x12345678abcdef01ull;
    bool enabled = true;
    unsigned calls, lookups, cases;
    struct Arguments
    {
        int32_t local = 0;
        const void *weapon = reinterpret_cast<const void *>(uintptr_t(0x12340));
        int32_t hand = 0, animation = 70;
        uint32_t index = 380;
        int32_t previous = 0;
        uint32_t previousIndex = 237;
        float time = 0.037f;
        uint8_t forced = 0;
    } wanted;

    void Reset()
    {
        enabled = true;
        WIB_ViewmodelAnimBlending = 1;
        WIB_ClientGlobals[0] = WIB_ClientGlobals[1] = reinterpret_cast<uint8_t *>(&client);
        client = {};
        client.ps.scriptAnimation = 37;
        // Exit ownership must not depend on an active scripted state or flag.
        assert(!client.ps.weaponFlags[1] && !client.ps.hands[0].state);
        wanted = {};
        calls = lookups = 0;
    }

    void Check(const char *name, float expected, bool lookup = true)
    {
        const auto passed = wanted;
        wanted.time = expected;
        const auto result = DW_WeaponInspectBlend_StartWeaponAnim(passed.local, passed.weapon,
            passed.hand, passed.animation, passed.index, passed.previous, passed.previousIndex,
            passed.time, passed.forced);
        assert(result == NativeResult && calls == 1);
        assert(lookups == (lookup ? 1u : 0u));
        ++cases;
        printf("CASE\t%s\n", name);
    }
}

extern "C"
{
    uint8_t *WIB_ClientGlobals[2]{};
    uint8_t WIB_ViewmodelAnimBlending = 1;
    bool DW_LocalBackend_IsEnabled() { return enabled; }
    bool DW_WeaponInspect_HasClip(const DWInspectPlayerState *ps)
    {
        assert(ps == &client.ps);
        ++lookups;
        return ps->scriptAnimation == 37;
    }
    uint64_t WIB_OriginalStartWeaponAnim(int32_t local, const void *weapon,
        int32_t hand, int32_t animation, uint32_t index, int32_t previous,
        uint32_t previousIndex, float time, uint8_t forced)
    {
        assert(local == wanted.local && weapon == wanted.weapon && hand == wanted.hand);
        assert(animation == wanted.animation && index == wanted.index);
        assert(previous == wanted.previous && previousIndex == wanted.previousIndex);
        assert(time == wanted.time && forced == wanted.forced);
        ++calls;
        return NativeResult;
    }
}

int main()
{
    for (int previous = 0; previous < 2; ++previous)
    {
        Reset();
        wanted.previous = previous;
        Check(previous ? "idle1-entry100ms" : "idle0-entry100ms", 0.1f);
    }
    {
        Reset();
        wanted.previous = -129;
        wanted.previousIndex = 236;
        Check("first-rebuilt-tree-sentinel-entry100ms", 0.1f);
    }
    {
        Reset();
        wanted.previous = -129;
        wanted.previousIndex = 237;
        Check("reset-sentinel-wrong-idle-node-unchanged", 0.037f);
    }
    {
        Reset();
        client.ps.scriptAnimation = 99;
        wanted.previous = -129;
        wanted.previousIndex = 236;
        Check("reset-sentinel-unrelated-scripted-clip-unchanged", 0.037f);
    }
    constexpr int shortExit[] = {0, 1, 2, 3, 28, 10, 11, 12, 71};
    constexpr int longExit[] = {16, 17, 18, 19, 20, 13, 22, 24, 25, 27, 61, 70};
    for (int animation : shortExit)
    {
        Reset();
        wanted.animation = animation;
        wanted.index = 237;
        wanted.previous = 70;
        wanted.previousIndex = 380;
        char name[64];
        snprintf(name, sizeof(name), "translated-exit-%d-100ms", animation);
        Check(name, 0.1f);
    }
    for (int animation : longExit)
    {
        Reset();
        wanted.animation = animation;
        wanted.index = animation == 70 ? 380 : 292;
        wanted.previous = 70;
        wanted.previousIndex = 380;
        char name[64];
        snprintf(name, sizeof(name), "translated-exit-%d-200ms", animation);
        Check(name, 0.2f);
    }
    for (unsigned guard = 0; guard < 10; ++guard)
    {
        Reset();
        if (guard == 0) enabled = false;
        if (guard == 1) WIB_ViewmodelAnimBlending = 0;
        if (guard == 2) wanted.forced = 0xf7;
        if (guard == 3) wanted.local = -1;
        if (guard == 4) wanted.local = 2;
        if (guard == 5) wanted.hand = 1;
        if (guard == 6) WIB_ClientGlobals[0] = nullptr;
        if (guard == 7) client.ps.scriptAnimation = 99;
        if (guard == 8) wanted.index = 381;
        if (guard == 9) wanted.previous = 32;
        const char *names[] = {"backend-off", "native-blending-off", "explicit-forced-transition",
            "negative-local", "out-of-range-local", "other-hand", "null-client-globals",
            "unrelated-scripted-clip", "wrong-scripted-node", "unsupported-entry-state"};
        Check(names[guard], 0.037f, guard >= 7);
    }
    {
        Reset();
        wanted.local = 1;
        Check("second-native-local-index", 0.1f);
    }
    {
        Reset();
        wanted.animation = 32; wanted.index = 337;
        wanted.previous = 70; wanted.previousIndex = 380;
        Check("unlisted-sprint-exit-keeps-native-policy", 0.037f);
    }
    {
        Reset();
        wanted.animation = 1; wanted.index = 237;
        wanted.previous = 70; wanted.previousIndex = 381;
        Check("wrong-outgoing-node-keeps-native-policy", 0.037f);
    }
    {
        Reset();
        wanted.animation = 1; wanted.index = 237;
        wanted.previous = 0; wanted.previousIndex = 237;
        Check("ordinary-idle-transition-unchanged", 0.037f);
    }
    printf("PASS WEAPON_INSPECT_BLEND cases=%u\n", cases);
    return 0;
}
