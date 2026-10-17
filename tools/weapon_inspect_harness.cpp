// Execute the byte-identical production owner with only WIR/native boundaries modeled.
#include "DW_WeaponInspect.h"
#include "DW_WeaponInspectBindings.h"
#include "DW_WeaponInspectAssets.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

namespace
{
    constexpr uint32_t AnimationA = 37, AnimationB = 38;
    constexpr uint8_t OriginalResult = 0xa5;
    unsigned nextClient, cases;

    struct Fixture
    {
        DWInspectPlayerState ps{};
        DWInspectPmove pm{};
        DWInspectWeapon weapon{};
        DWInspectAnimationPackage packageA{"fixture_package_a"}, packageB{"fixture_package_b"};
        DWInspectWeaponDefinition definitionA{}, definitionB{}, unsupported{}, noPackage{}, noName{};
        DWInspectAnimationPackage unsupportedPackage{"fixture_not_supported"}, unnamedPackage{nullptr};
        void *connection = reinterpret_cast<void *>(uintptr_t(0x12340));
        void *pml = reinterpret_cast<void *>(uintptr_t(0x5550));
        uint32_t clock = 1000, weaponCount = 8, lastHand = 0;
        bool enabled = true, mainThread = true, connected = true, sprinting = false,
             skydiving = false, mounted = false, scriptedScene = false, alternate = false,
             viewAvailable = true, requestedAvailable = true, indexAvailable = true,
             nameAvailable = true, zeroIndex = false;
        bool commitSprint = false, expectSprintUnblocked = false, mutateSprintFlag = false;
        unsigned reliable = 0, plays = 0, originalCalls = 0, nextAnimations = 0, idleCalls = 0;
        unsigned sprintCalls = 0;
        const char *reliableText = nullptr;
        DWInspectPmove *originalPmove = nullptr;
        void *originalPml = nullptr;
        uint32_t playedIndex = 0;
        int32_t playedStart = 0, playedDuration = 0;

        Fixture();
        void Queue() { DW_WeaponInspect_ServerRequest(ps.clientNumber, &ps); }
        void Step()
        {
            assert(DW_WeaponInspect_PMove(&pm, pml) == OriginalResult);
            assert(originalPmove == &pm && originalPml == pml);
        }
        void Start()
        {
            Queue();
            const DWInspectUserCmd before = pm.command;
            Step();
            assert(plays == 1 && playedIndex == AnimationA && playedStart == pm.command.serverTime);
            assert(playedDuration == int32_t(kDWWeaponInspectAssets[0].durationMs));
            assert((ps.weaponFlags[1] & 0x400) && ps.hands[0].state == 62);
            assert(!memcmp(&before, &pm.command, sizeof(before)));
        }
        void Cancelled() const
        {
            assert(plays == 1 && nextAnimations == 0 && idleCalls == 1);
            assert(!(ps.weaponFlags[1] & 0x400));
            assert(ps.scriptAnimation == playedIndex && ps.scriptStartTime == playedStart);
            assert(!ps.hands[0].state && !ps.hands[0].weaponTime && !ps.hands[0].weaponDelay);
        }
    } *current;

    void Passed(const char *name)
    {
        ++cases;
        printf("CASE\t%s\n", name);
    }

    void SameClient(const DWInspectPlayerState *ps)
    {
        assert(ps && ps->clientNumber == current->ps.clientNumber);
    }
}

extern "C"
{
    const DWInspectWeaponDefinition *WIR_WeaponDefinitions[8]{};
    uint32_t WIR_MpFlagValue = 1;
    void *WIR_ClientConnection = nullptr;
    uint8_t WIR_ConnectionType = 2;

    bool DW_LocalBackend_IsEnabled() { return current->enabled; }
    uint32_t WIR_Milliseconds() { return current->clock; }
    bool WIR_IsMainThread() { return current->mainThread; }
    bool WIR_IsConnected(uint32_t local)
    {
        assert(local == 0);
        return current->connected;
    }
    void WIR_AddReliableCommand(void *connection, const char *text)
    {
        assert(connection == current->connection);
        assert(!strcmp(text, "dw_inspect"));
        ++current->reliable;
        current->reliableText = text;
    }
    const DWInspectWeapon *WIR_ViewmodelWeapon(const void *map, const DWInspectPlayerState *ps)
    {
        SameClient(ps);
        assert(map == current->pm.weaponMap);
        return current->viewAvailable ? &current->weapon : nullptr;
    }
    const DWInspectWeapon *WIR_RequestedWeapon(const DWInspectPmove *pm)
    {
        SameClient(pm->ps);
        return current->requestedAvailable ? &pm->command.weapon : nullptr;
    }
    uint32_t WIR_WeaponCount() { return current->weaponCount; }
    int32_t WIR_LastHand(const void *map, const DWInspectPlayerState *ps)
    {
        SameClient(ps);
        assert(map == current->pm.weaponMap);
        return int32_t(current->lastHand);
    }
    bool WIR_UsingAlternate(const DWInspectPlayerState *ps) { SameClient(ps); return current->alternate; }
    bool WIR_IsSprinting(const DWInspectPlayerState *ps) { SameClient(ps); return current->sprinting; }
    bool WIR_IsSkydiving(const DWInspectPlayerState *ps) { SameClient(ps); return current->skydiving; }
    bool WIR_IsMounted(const DWInspectPlayerState *ps) { SameClient(ps); return current->mounted; }
    bool WIR_IsScriptedScene(const DWInspectPlayerState *ps) { SameClient(ps); return current->scriptedScene; }
    bool WIR_AnimationIndex(uint32_t type, const char *name, uint32_t *index)
    {
        assert(type == 16 && name && index);
        if (!current->indexAvailable)
            return false;
        if (!strcmp(name, kDWWeaponInspectAssets[0].animation))
            *index = current->zeroIndex ? 0 : AnimationA;
        else if (!strcmp(name, kDWWeaponInspectAssets[1].animation))
            *index = current->zeroIndex ? 0 : AnimationB;
        else
            return false;
        return true;
    }
    bool WIR_AnimationName(uint32_t type, uint32_t index, const char **name)
    {
        assert(type == 16 && name);
        if (!current->nameAvailable)
            return false;
        *name = index == AnimationA ? kDWWeaponInspectAssets[0].animation :
                index == AnimationB ? kDWWeaponInspectAssets[1].animation : "fixture_unrelated_scripted_animation";
        return true;
    }
    bool WIR_PlayScripted(const void *map, DWInspectPlayerState *ps, uint32_t animation,
                         int32_t start, int32_t duration, uint32_t hand)
    {
        assert(map == current->pm.weaponMap && ps == &current->ps && hand == 0);
        assert(animation == AnimationA || animation == AnimationB);
        ++current->plays;
        current->playedIndex = animation;
        current->playedStart = start;
        current->playedDuration = duration;
        // Model the native setter's ownership fields, exercising the real
        // production OwnedAnimation/CancelOwned path on subsequent frames.
        ps->weaponFlags[1] |= 0x400;
        ps->scriptAnimation = animation;
        ps->scriptStartTime = start;
        ps->hands[0].state = 62;
        ps->hands[0].animation = 70;
        ps->hands[0].weaponTime = duration;
        return true;
    }
    void WIR_WeaponIdle(DWInspectPlayerState *ps, void *handler, const void *map, uint32_t hand)
    {
        assert(ps == &current->ps && handler == current->pm.handler && map == current->pm.weaponMap && !hand);
        ++current->idleCalls;
        // Replay's actual Idle resets the state/time and selects animation0.
        // It deliberately retains the scripted clip index and start time.
        ps->hands[0].state = 0;
        ps->hands[0].weaponTime = 0;
        ps->hands[0].animation = 0;
    }
    uint8_t WIR_OriginalWeapon(DWInspectPmove *pm, void *pml)
    {
        ++current->originalCalls;
        current->originalPmove = pm;
        current->originalPml = pml;
        return OriginalResult;
    }
    uint8_t WIR_OriginalUpdateSprint(DWInspectPmove *pm, void *pml)
    {
        ++current->sprintCalls;
        current->originalPmove = pm;
        current->originalPml = pml;
        if (current->expectSprintUnblocked)
            assert(pm && pm->ps && !(pm->ps->weaponFlags[1] & 0x400));
        if (current->mutateSprintFlag)
            pm->ps->weaponFlags[1] |= 0x80;
        if (current->commitSprint)
        {
            current->sprinting = true;
            pm->ps->movementFlags[0] |= 0x100000;
        }
        return 0x5b;
    }
}

namespace
{
Fixture::Fixture()
{
    current = this;
    assert(nextClient < 200);
    ps.clientNumber = int32_t(nextClient++); // isolate the production pending slots without a test-only reset API
    pm.ps = &ps;
    pm.handler = reinterpret_cast<void *>(uintptr_t(0x2000));
    pm.weaponMap = reinterpret_cast<void *>(uintptr_t(0x3000));
    pm.command.serverTime = 1000;
    weapon.index = 1;
    weapon.remaining[57] = 0x6a;
    pm.command.weapon = weapon;
    definitionA.primaryAnimationPackage = &packageA;
    definitionB.primaryAnimationPackage = &packageB;
    unsupported.primaryAnimationPackage = &unsupportedPackage;
    noName.primaryAnimationPackage = &unnamedPackage;
    WIR_WeaponDefinitions[0] = nullptr;
    WIR_WeaponDefinitions[1] = &definitionA;
    WIR_WeaponDefinitions[2] = &definitionB;
    WIR_WeaponDefinitions[3] = &unsupported;
    WIR_WeaponDefinitions[4] = nullptr;
    WIR_WeaponDefinitions[5] = &noPackage;
    WIR_WeaponDefinitions[6] = &noName;
    WIR_WeaponDefinitions[7] = nullptr;
    WIR_ClientConnection = connection;
    WIR_ConnectionType = 2;
    WIR_MpFlagValue = 1;
}
}

int main()
{
    static_assert(sizeof(kDWWeaponInspectAssets)/sizeof(*kDWWeaponInspectAssets) == 2);
    {
        Fixture f;
        f.pm.command.buttons = uint64_t(1) << 44;
        const auto before = f.pm.command;
        DW_WeaponInspect_Request(0);
        assert(f.reliable == 1 && !strcmp(f.reliableText, "dw_inspect") && !f.plays);
        assert(!memcmp(&before, &f.pm.command, sizeof(before)));
        f.Step(); // sending a reliable command does not speculate local playback
        assert(!f.plays);
        Passed("request-one-reliable-command-without-usercmd-bits-or-local-playback");
    }
    struct RequestGuard { const char *name; void (*change)(Fixture &); } requestGuards[] = {
        {"request-backend-disabled", [](Fixture &f) { f.enabled = false; }},
        {"request-not-main-thread", [](Fixture &f) { f.mainThread = false; }},
        {"request-not-connected", [](Fixture &f) { f.connected = false; }},
        {"request-wrong-connection-type", [](Fixture &) { WIR_ConnectionType = 1; }},
        {"request-null-connection", [](Fixture &) { WIR_ClientConnection = nullptr; }},
    };
    for (const auto &guard : requestGuards)
    {
        Fixture f;
        guard.change(f);
        const auto before = f.pm.command;
        DW_WeaponInspect_Request(0);
        assert(!f.reliable && !f.plays && !memcmp(&before, &f.pm.command, sizeof(before)));
        Passed(guard.name);
    }
    {
        Fixture f;
        DW_WeaponInspect_Request(1);
        assert(!f.reliable);
        Passed("request-rejects-other-local-client");
    }
    for (unsigned bad = 0; bad < 6; ++bad)
    {
        Fixture f;
        if (bad == 0) DW_WeaponInspect_ServerRequest(-1, &f.ps);
        if (bad == 1) DW_WeaponInspect_ServerRequest(200, &f.ps);
        if (bad == 2) DW_WeaponInspect_ServerRequest(f.ps.clientNumber, nullptr);
        if (bad == 3) DW_WeaponInspect_ServerRequest(f.ps.clientNumber+1, &f.ps);
        if (bad == 4) { f.ps.movementType = 1; f.Queue(); f.ps.movementType = 0; }
        if (bad == 5) { f.enabled = false; f.Queue(); f.enabled = true; }
        f.Step();
        assert(!f.plays && f.originalCalls == 1);
        Passed(bad == 0 ? "server-rejects-negative-client" : bad == 1 ? "server-rejects-client-200" :
               bad == 2 ? "server-rejects-null-playerstate" : bad == 3 ? "server-rejects-client-number-mismatch" :
               bad == 4 ? "server-rejects-nonliving-movement" : "server-rejects-disabled-backend");
    }
    {
        Fixture f;
        f.Queue();
        auto predictedState = f.ps;
        auto predictedMove = f.pm;
        predictedMove.ps = &predictedState;
        assert(DW_WeaponInspect_PMove(&predictedMove, f.pml) == OriginalResult);
        assert(!f.plays && !predictedState.scriptAnimation);
        f.Step();
        assert(f.plays == 1 && f.ps.scriptAnimation == AnimationA);
        assert(!predictedState.scriptAnimation);
        Passed("different-prediction-playerstate-cannot-consume-authenticated-server-request");
    }
    {
        Fixture f;
        f.Start();
        assert(f.playedDuration == 500 && f.originalCalls == 1 && !f.reliable);
        f.Step();
        assert(f.plays == 1 && !f.idleCalls);
        Passed("valid-start-preserves-native-index-time-duration-and-consumes-once");
    }
    struct StartGuard { const char *name; void (*change)(Fixture &); } startGuards[] = {
        {"start-movement-mode", [](Fixture &f) { f.ps.movementType = 1; }},
        {"start-null-weapon-map", [](Fixture &f) { f.pm.weaponMap = nullptr; }},
        {"start-null-handler", [](Fixture &f) { f.pm.handler = nullptr; }},
        {"start-attack-held", [](Fixture &f) { f.pm.command.buttons = 1; }},
        {"start-reload-held", [](Fixture &f) { f.pm.command.buttons = 0x20; }},
        {"start-weapon-exclusion-flag", [](Fixture &f) { f.ps.weaponFlags[0] = 2; }},
        {"start-special-movement", [](Fixture &f) { f.ps.movementFlags[0] = 0x20; }},
        {"start-other-gameplay-exclusion", [](Fixture &f) { f.ps.otherFlags[0] = 0x800; }},
        {"start-mp-other-exclusion", [](Fixture &f) { f.ps.otherFlags[1] = 1u << 22; }},
        {"start-ads", [](Fixture &f) { f.ps.adsFraction = 0.01f; }},
        {"start-sprinting", [](Fixture &f) { f.sprinting = true; }},
        {"start-skydiving", [](Fixture &f) { f.skydiving = true; }},
        {"start-mounted", [](Fixture &f) { f.mounted = true; }},
        {"start-scripted-scene", [](Fixture &f) { f.scriptedScene = true; }},
        {"start-alternate-fire", [](Fixture &f) { f.alternate = true; }},
        {"start-second-hand-active", [](Fixture &f) { f.lastHand = 1; }},
        {"start-existing-script-owner", [](Fixture &f) { f.ps.weaponFlags[1] = 0x400; }},
        {"start-first-hand-state", [](Fixture &f) { f.ps.hands[0].state = 1; }},
        {"start-first-hand-time", [](Fixture &f) { f.ps.hands[0].weaponTime = 1; }},
        {"start-first-hand-delay", [](Fixture &f) { f.ps.hands[0].weaponDelay = 1; }},
        {"start-second-hand-state", [](Fixture &f) { f.ps.hands[1].state = 1; }},
        {"start-second-hand-time", [](Fixture &f) { f.ps.hands[1].weaponTime = 1; }},
        {"start-second-hand-delay", [](Fixture &f) { f.ps.hands[1].weaponDelay = 1; }},
        {"start-missing-viewmodel", [](Fixture &f) { f.viewAvailable = false; }},
        {"start-missing-requested-weapon", [](Fixture &f) { f.requestedAvailable = false; }},
        {"start-full-weapon-attachment-change", [](Fixture &f) { f.pm.command.weapon.remaining[57] ^= 1; }},
        {"start-weapon-zero", [](Fixture &f) { f.weapon.index = 0; f.pm.command.weapon = f.weapon; }},
        {"start-weapon-out-of-range", [](Fixture &f) { f.weapon.index = 8; f.pm.command.weapon = f.weapon; }},
        {"start-unsupported-package", [](Fixture &f) { f.weapon.index = 3; f.pm.command.weapon = f.weapon; }},
        {"start-null-definition", [](Fixture &f) { f.weapon.index = 4; f.pm.command.weapon = f.weapon; }},
        {"start-null-package", [](Fixture &f) { f.weapon.index = 5; f.pm.command.weapon = f.weapon; }},
        {"start-null-package-name", [](Fixture &f) { f.weapon.index = 6; f.pm.command.weapon = f.weapon; }},
        {"start-ncs-lookup-failed", [](Fixture &f) { f.indexAvailable = false; }},
        {"start-ncs-index-zero", [](Fixture &f) { f.zeroIndex = true; }},
    };
    for (const auto &guard : startGuards)
    {
        Fixture f;
        f.Queue();
        guard.change(f);
        const auto before = f.pm.command;
        f.Step();
        assert(!f.plays && !f.idleCalls && f.originalCalls == 1);
        assert(!memcmp(&before, &f.pm.command, sizeof(before)));
        Passed(guard.name);
    }
    for (unsigned action = 0; action < 4; ++action)
    {
        Fixture f;
        f.ps.weaponFlags[1] = 0x20;
        f.Start();
        if (action == 0) f.pm.command.buttons = 1;
        if (action == 1) f.pm.command.buttons = 0x20;
        if (action == 2) f.pm.command.weapon.remaining[57] ^= 0x80;
        if (action == 3) { f.weapon.index = 2; f.pm.command.weapon = f.weapon; }
        f.Step();
        f.Cancelled();
        assert(f.ps.weaponFlags[1] == 0x20);
        Passed(action == 0 ? "cancel-owned-on-attack" : action == 1 ? "cancel-owned-on-reload" :
               action == 2 ? "cancel-owned-on-attachment-selection-change" : "cancel-owned-on-current-package-change");
    }
    {
        Fixture f;
        f.ps.weaponFlags[1] = 0x420;
        f.ps.scriptAnimation = 99;
        f.ps.scriptStartTime = 700;
        f.ps.hands[0].state = 62;
        f.ps.hands[0].weaponTime = 123;
        f.pm.command.buttons = 1;
        const auto before = f.ps;
        f.Step();
        assert(!f.plays && !f.idleCalls && !f.nextAnimations);
        assert(!memcmp(&before, &f.ps, sizeof(before)));
        Passed("unrelated-scripted-animation-is-never-cancelled");
    }
    {
        Fixture f;
        f.Start();
        f.pm.command.serverTime = f.playedStart+f.playedDuration-1;
        f.Step();
        assert(!f.idleCalls && f.ps.scriptAnimation == AnimationA);
        ++f.pm.command.serverTime;
        f.Step();
        f.Cancelled();
        Passed("owned-animation-cancels-at-exact-duration");
    }
    {
        Fixture f;
        f.pm.command.serverTime = -16;
        f.Start();
        f.pm.command.serverTime = 483;
        f.Step();
        assert(!f.idleCalls);
        f.pm.command.serverTime = 484;
        f.Step();
        f.Cancelled();
        Passed("owned-animation-duration-across-server-clock-wrap");
    }
    for (unsigned wrapped = 0; wrapped < 2; ++wrapped)
        for (unsigned expired = 0; expired < 2; ++expired)
        {
            Fixture f;
            f.clock = wrapped ? 0xfffffff0u : 1000;
            f.Queue();
            f.clock += expired ? 251u : 250u;
            f.Step();
            assert(f.plays == (expired ? 0u : 1u));
            Passed(wrapped ? (expired ? "queue-wrap-age251-expires" : "queue-wrap-age250-accepted") :
                   (expired ? "queue-age251-expires" : "queue-age250-accepted"));
        }
    for (unsigned missing = 0; missing < 4; ++missing)
    {
        Fixture f;
        DWInspectPmove *pm = &f.pm;
        void *pml = f.pml;
        if (missing == 0) f.enabled = false;
        if (missing == 1) pm = nullptr;
        if (missing == 2) f.pm.ps = nullptr;
        if (missing == 3) pml = nullptr;
        assert(DW_WeaponInspect_PMove(pm, pml) == OriginalResult && f.originalCalls == 1);
        assert(f.originalPmove == pm && f.originalPml == pml && !f.plays);
        Passed(missing == 0 ? "pmove-disabled-backend-retains-original" : missing == 1 ? "pmove-null-context-retains-original" :
               missing == 2 ? "pmove-null-playerstate-retains-original" : "pmove-null-local-context-retains-original");
    }
    for (unsigned commit = 0; commit < 2; ++commit)
    {
        Fixture f;
        f.Start();
        f.ps.weaponFlags[1] |= 0x20;
        f.expectSprintUnblocked = f.mutateSprintFlag = true;
        f.commitSprint = commit != 0;
        const auto before = f.pm.command;
        assert(DW_WeaponInspect_UpdateSprint(&f.pm, f.pml) == 0x5b);
        assert(f.sprintCalls == 1 && !memcmp(&before, &f.pm.command, sizeof(before)));
        assert(f.ps.weaponFlags[1] == (commit ? 0xa0u : 0x4a0u));
        if (commit)
        {
            f.Cancelled();
            assert(f.ps.movementFlags[0] & 0x100000);
            assert(!DW_WeaponInspect_IsActive(&f.ps) && DW_WeaponInspect_HasClip(&f.ps));
        }
        else
            assert(!f.idleCalls && DW_WeaponInspect_IsActive(&f.ps));
        Passed(commit ? "native-sprint-commit-cancels-owned-inspect-without-losing-native-sideeffects" :
                        "blocked-native-sprint-restores-only-inspect-flag-without-cancelling");
    }
    for (unsigned missing = 0; missing < 5; ++missing)
    {
        Fixture f;
        auto *pm = &f.pm;
        auto *pml = f.pml;
        if (missing == 0) f.enabled = false;
        if (missing == 1) pm = nullptr;
        if (missing == 2) f.pm.ps = nullptr;
        if (missing == 3) pml = nullptr;
        if (missing == 4)
        {
            f.ps.weaponFlags[1] = 0x400;
            f.ps.scriptAnimation = 99;
            f.ps.hands[0].state = 62;
        }
        const auto before = f.ps;
        assert(DW_WeaponInspect_UpdateSprint(pm, pml) == 0x5b && f.sprintCalls == 1);
        assert(f.originalPmove == pm && f.originalPml == pml);
        assert(!f.idleCalls && !memcmp(&before, &f.ps, sizeof(before)));
        Passed(missing == 0 ? "sprint-disabled-backend-retains-native" : missing == 1 ? "sprint-null-context-retains-native" :
            missing == 2 ? "sprint-null-playerstate-retains-native" : missing == 3 ? "sprint-null-local-context-retains-native" :
            "sprint-unrelated-script-retains-native");
    }
    {
        Fixture f;
        assert(!DW_WeaponInspect_HasClip(nullptr) && !DW_WeaponInspect_IsActive(nullptr));
        assert(!DW_WeaponInspect_HasClip(&f.ps) && !DW_WeaponInspect_IsActive(&f.ps));
        f.Start();
        assert(DW_WeaponInspect_HasClip(&f.ps) && DW_WeaponInspect_IsActive(&f.ps));
        f.enabled = false;
        assert(!DW_WeaponInspect_HasClip(&f.ps) && !DW_WeaponInspect_IsActive(&f.ps));
        f.enabled = true;
        f.ps.scriptAnimation = 99;
        assert(!DW_WeaponInspect_HasClip(&f.ps) && !DW_WeaponInspect_IsActive(&f.ps));
        f.ps.scriptAnimation = AnimationA;
        f.nameAvailable = false;
        assert(!DW_WeaponInspect_HasClip(&f.ps) && !DW_WeaponInspect_IsActive(&f.ps));
        Passed("hud-and-blend-ownership-helpers-reject-null-disabled-foreign-and-unavailable-clips");
    }
    printf("PASS WEAPON_INSPECT_RUNTIME cases=%u\n", cases);
    return 0;
}
