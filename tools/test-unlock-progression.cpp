// Compile the actual getter source with isolated native/Lua boundaries.
#include <cassert>
#include <cstring>
#include <cstdio>
#include "../integration/replay/DW_Unlocks.cpp"

namespace
{
    struct LuaFixture
    {
        int count = 1, controller = 0, season = 0;
        bool valid = true;
        const char *reference = nullptr;
        double value = 0;
        uint64_t xp = 0, rank = 0;
    };
    bool provider = true, unlock = false;
    alignas(8) uint8_t player[20000]{};
}
extern "C"
{
    uint8_t gl_14414CC80[8192]{};
    uint64_t gl_1444879C8[16]{};
    bool DW_LocalBackend_IsEnabled() { return provider; }
    bool DW_LocalConfig_UnlockAll() { return unlock; }
    void *func_14105BC30() { return player; }
    int func_1420838B0(void *vm) { return static_cast<LuaFixture *>(vm)->count; }
    int func_1420839E0(void *vm, int) { return static_cast<LuaFixture *>(vm)->valid; }
    int func_142083A30(void *vm, int) { return static_cast<LuaFixture *>(vm)->reference != nullptr; }
    int func_1419CE9B0(void *vm, int index)
    { auto &v = *static_cast<LuaFixture *>(vm); return index == 1 ? v.controller : v.season; }
    const char *func_142084950(void *vm, int, size_t *)
    { return static_cast<LuaFixture *>(vm)->reference; }
    void func_142084100(void *vm, double value) { static_cast<LuaFixture *>(vm)->value = value; }
    void func_1420833B0(void *, int, int) {}
    void func_1419CE4F0(const char *key, uint64_t value, void *vm)
    { auto &v = *static_cast<LuaFixture *>(vm); (key[0] == 'x' ? v.xp : v.rank) = value; }
    int func_142089FB0(void *, const char *, ...) { return -1; }
    int func_140D66C20(int controller) { return controller >= 0 && controller < 2 ? controller : -1; }
}

extern "C" __declspec(dllexport) double DWFixture_Player(
    int kind, bool enabled, uint64_t xp, uint64_t rank, int season)
{
    provider = true; unlock = enabled;
    auto *values = reinterpret_cast<uint64_t *>(player);
    values[8] = xp; values[9] = rank;
    for (unsigned index = 0; index < 7; ++index)
    { values[10 + 2 * index] = 0; values[11 + 2 * index] = 0; }
    gl_1444879C8[0] = 0;
    LuaFixture vm;
    vm.count = kind == 2 || kind == 3 ? 2 : 1;
    vm.season = season;
    int result = kind == 0 ? func_1410592B0(&vm) :
                 kind == 1 ? func_141059360(&vm) :
                 kind == 2 ? func_141059410(&vm) :
                 kind == 3 ? func_141059500(&vm) : func_141059A80(&vm);
    assert(result == 1);
    return vm.value;
}

extern "C" __declspec(dllexport) uint64_t DWFixture_Weapon(
    const char *reference, bool enabled, uint64_t xp, uint64_t rank, bool rankValue, int client)
{
    provider = true; unlock = enabled;
    auto &weapons = reinterpret_cast<GunsmithPrefix *>(gl_14414CC80)->clients[client];
    weapons.count = 1; weapons.weapons[0] = {reference, 2000001, xp, rank};
    uint8_t before[sizeof(gl_14414CC80)];
    std::memcpy(before, gl_14414CC80, sizeof(before));
    LuaFixture vm; vm.count = 2; vm.reference = reference; vm.controller = client;
    assert(func_140F58C60(&vm) == 1);
    assert(weapons.weapons[0].xp == xp && weapons.weapons[0].rank == rank);
    assert(std::memcmp(before, gl_14414CC80, sizeof(before)) == 0);
    return rankValue ? vm.rank : vm.xp;
}

int main()
{
    auto *values = reinterpret_cast<uint64_t *>(player);
    values[8] = 17500; values[9] = 4;
    for (unsigned season = 0; season < 7; ++season)
    { values[10 + 2 * season] = 3000 + season; values[11 + 2 * season] = season; }
    gl_1444879C8[0] = 11;
    uint8_t originalPlayer[sizeof(player)], originalWeapons[sizeof(gl_14414CC80)];
    std::memcpy(originalPlayer, player, sizeof(player));
    auto &weapons = reinterpret_cast<GunsmithPrefix *>(gl_14414CC80)->clients[0];
    LuaFixture vm;
    assert(func_1410592B0(&vm) == 1 && vm.value == 17500);
    assert(func_141059360(&vm) == 1 && vm.value == 4);
    assert(func_141059A80(&vm) == 1 && vm.value == 11);
    unlock = true;
    assert(func_1410592B0(&vm) == 1 && vm.value == 960000);
    assert(func_141059360(&vm) == 1 && vm.value == 54);
    assert(func_141059A80(&vm) == 1 && vm.value == 0);
    vm.count = 2;
    for (unsigned season = 0; season < 7; ++season)
    {
        vm.season = season;
        assert(func_141059410(&vm) == 1 && vm.value == dwReplayMaximumSeasonXp[season]);
        assert(func_141059500(&vm) == 1 && vm.value == 99);
    }
    assert(std::memcmp(originalPlayer, player, sizeof(player)) == 0);
    unsigned tested = 0;
    for (const auto &cap : dwReplayWeaponCaps)
    {
        weapons.count = 1;
        weapons.weapons[0] = {cap.reference, 2000000 + tested, 1234, 2};
        std::memcpy(originalWeapons, gl_14414CC80, sizeof(gl_14414CC80));
        vm.reference = cap.reference;
        assert(func_140F58C60(&vm) == 1 && vm.xp == cap.xp && vm.rank == cap.rank);
        assert(std::memcmp(originalWeapons, gl_14414CC80, sizeof(gl_14414CC80)) == 0);
        weapons.weapons[0].xp += 100; weapons.weapons[0].rank = 3;
        unlock = false;
        assert(func_140F58C60(&vm) == 1 && vm.xp == 1334 && vm.rank == 3);
        unlock = true; provider = false;
        assert(func_140F58C60(&vm) == 1 && vm.xp == 1334 && vm.rank == 3);
        provider = true;
        ++tested;
    }
    assert(tested == 51);
    for (int client = 0; client < 2; ++client)
        for (const auto &cap : dwReplayWeaponCaps)
        {
            const uint64_t earnedXp = 1334 + client * 100;
            assert(DWFixture_Weapon(cap.reference, false, earnedXp, 3 + client, false, client) == earnedXp);
            assert(DWFixture_Weapon(cap.reference, false, earnedXp, 3 + client, true, client) == 3 + client);
            assert(DWFixture_Weapon(cap.reference, true, earnedXp, 3 + client, false, client) == cap.xp);
            assert(DWFixture_Weapon(cap.reference, true, earnedXp, 3 + client, true, client) == cap.rank);
            provider = false;
            vm.controller = client; vm.count = 2; vm.reference = cap.reference;
            assert(func_140F58C60(&vm) == 1 && vm.xp == earnedXp && vm.rank == 3 + client);
            provider = true;
        }
    vm.controller = 0;
    weapons.count = 0;
    vm.reference = dwReplayWeaponCaps[0].reference;
    assert(func_140F58C60(&vm) == 1 && vm.rank == dwReplayWeaponCaps[0].rank);
    vm.reference = "unknown_weapon";
    assert(func_140F58C60(&vm) == 1 && vm.xp == 0 && vm.rank == 0);
    values[8] += 700; values[9] = 5;
    unlock = false; vm.count = 1;
    assert(func_1410592B0(&vm) == 1 && vm.value == 18200);
    assert(func_141059360(&vm) == 1 && vm.value == 5);
    assert(gl_1444879C8[0] == 11);
    for (unsigned index = 0; index < 120; ++index) values[8 + index] = 1000 + index * 37;
    for (unsigned index = 0; index < 16; ++index) gl_1444879C8[index] = index;
    for (int controller = 0; controller < 8; ++controller)
    {
        vm.controller = controller; vm.count = 1;
        assert(func_1410592B0(&vm) == 1 && vm.value == values[8 + 2 * controller]);
        assert(func_141059360(&vm) == 1 && vm.value == values[9 + 2 * controller]);
        assert(func_141059A80(&vm) == 1 && vm.value == 2 * controller);
        vm.count = 2;
        for (int season = 0; season < 7; ++season)
        {
            vm.season = season;
            assert(func_141059410(&vm) == 1 && vm.value == values[10 + 2 * (7 * controller + season)]);
            assert(func_141059500(&vm) == 1 && vm.value == values[11 + 2 * (7 * controller + season)]);
        }
    }
    vm.count = 1;
    vm.valid = false;
    assert(func_1410592B0(&vm) == -1);
    std::puts("PASS: actual six getter bodies, all 51 caps, seven seasons, reversible projection and unchanged native storage");
}
