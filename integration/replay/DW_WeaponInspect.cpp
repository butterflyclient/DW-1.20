#include "DW_WeaponInspect.h"
#include "DW_WeaponInspectBindings.h"
#include "DW_WeaponInspectAssets.h"
#include <string.h>

extern "C" bool DW_LocalBackend_IsEnabled();

namespace
{
    constexpr uint32_t ClientCount = 200;
    constexpr uint32_t RequestExpiryMs = 250;
    // Native held sprint, auto sprint and input-device configuration are not
    // gameplay actions. All remaining action exclusions use verified buttons.
    constexpr uint64_t InterruptButtons = 1 | 4 | 0x20 | 0x200 | 0x100 |
        0x1000 | 0x2000 | 0x400000;
    constexpr uint32_t SpecialMovement = 0x20 | 0x40 | 0x8000 | 0x100000 | 0x20000000;
    constexpr uint32_t ScriptFlag = 0x400;
    constexpr int32_t ScriptedWeaponState = 62;
    constexpr uint32_t XAnimNetConstType = 16;

    struct Pending
    {
        uintptr_t playerState;
        uint32_t time;
        uint32_t locked;
    };
    Pending s_pending[ClientCount];

    bool TakeRequest(const DWInspectPlayerState *ps)
    {
        if (ps->clientNumber < 0 || uint32_t(ps->clientNumber) >= ClientCount)
            return false;
        auto &pending = s_pending[ps->clientNumber];
        if (!__atomic_load_n(&pending.playerState, __ATOMIC_ACQUIRE))
            return false;
        // A short, nonblocking lock keeps the pointer and its deadline paired.
        // Prediction on another thread may examine the same client number, but
        // only the authenticated server playerState can consume this request.
        if (__atomic_exchange_n(&pending.locked, 1u, __ATOMIC_ACQUIRE))
            return false;
        const uintptr_t queued = __atomic_load_n(&pending.playerState, __ATOMIC_RELAXED);
        const uint32_t time = __atomic_load_n(&pending.time, __ATOMIC_RELAXED);
        const bool expired = uint32_t(WIR_Milliseconds() - time) > RequestExpiryMs;
        const bool matches = queued == reinterpret_cast<uintptr_t>(ps);
        if (expired || matches)
            __atomic_store_n(&pending.playerState, uintptr_t(0), __ATOMIC_RELAXED);
        __atomic_store_n(&pending.locked, 0u, __ATOMIC_RELEASE);
        return queued && matches && !expired;
    }

    const DWWeaponInspectAsset *FindAnimation(const char *animation)
    {
        if (animation)
            for (const auto &asset : kDWWeaponInspectAssets)
                if (!strcmp(asset.animation, animation))
                    return &asset;
        return nullptr;
    }

    const DWWeaponInspectAsset *OwnedAnimation(const DWInspectPlayerState *ps)
    {
        if (!(ps->weaponFlags[1] & ScriptFlag) ||
            ps->hands[0].state != ScriptedWeaponState || !ps->scriptAnimation)
            return nullptr;
        const char *animation = nullptr;
        if (!WIR_AnimationName(XAnimNetConstType, ps->scriptAnimation, &animation))
            return nullptr;
        return FindAnimation(animation);
    }

    bool Eligible(DWInspectPmove *pm)
    {
        const auto *ps = pm->ps;
        // Only ordinary living movement is supported. Linked/noclip/spectator
        // and last-stand movement modes cannot enter this viewmodel action.
        if (ps->movementType != 0 || !pm->weaponMap || !pm->handler ||
            (pm->command.buttons & InterruptButtons) ||
            (ps->weaponFlags[0] & 2) ||
            (ps->movementFlags[0] & SpecialMovement) ||
            (ps->otherFlags[0] & 0x800) ||
            (ps->otherFlags[1] & (WIR_MpFlagValue << 22)) ||
            ps->adsFraction != 0.0f)
            return false;
        // These shipped predicates preserve their actual target layouts.
        return !WIR_IsSprinting(ps) && !WIR_IsSkydiving(ps) &&
            !WIR_IsMounted(ps) && !WIR_IsScriptedScene(ps) &&
            !WIR_UsingAlternate(ps) && WIR_LastHand(pm->weaponMap, ps) == 0;
    }

    bool WeaponSelectionChanged(DWInspectPmove *pm)
    {
        const auto *weapon = WIR_ViewmodelWeapon(pm->weaponMap, pm->ps);
        const auto *requested = WIR_RequestedWeapon(pm);
        // Compare the complete native Weapon, including attachments. The
        // scripted state must not postpone a requested switch, even between
        // two weapons that happen to use the same animation package.
        return !weapon || !requested || memcmp(weapon, requested, sizeof(*weapon)) != 0;
    }

    const DWWeaponInspectAsset *CurrentAsset(DWInspectPmove *pm)
    {
        const auto *weapon = WIR_ViewmodelWeapon(pm->weaponMap, pm->ps);
        if (!weapon || !weapon->index || weapon->index >= WIR_WeaponCount())
            return nullptr;
        const auto *definition = WIR_WeaponDefinitions[weapon->index];
        const auto *package = definition ? definition->primaryAnimationPackage : nullptr;
        if (!package || !package->name)
            return nullptr;
        for (const auto &asset : kDWWeaponInspectAssets)
            if (!strcmp(asset.package, package->name))
                return &asset;
        return nullptr;
    }

    void CancelOwned(DWInspectPmove *pm)
    {
        auto *ps = pm->ps;
        // Call only after OwnedAnimation succeeded. Other scripted animations,
        // reloads and weapon transitions keep their native state untouched.
        ps->weaponFlags[1] &= ~ScriptFlag;
        // Replay's state62 completion retains the clip identity and start time.
        // Clearing them forces CG_Weapon_ChangeViewmodelDobj to discard the
        // current XAnim tree, losing the outgoing pose before it can blend.
        // Native Idle owns the hand state, animation toggle and weapon timers.
        WIR_WeaponIdle(ps, pm->handler, pm->weaponMap, 0);
    }

    bool CanStart(DWInspectPmove *pm)
    {
        if (!Eligible(pm) || (pm->ps->weaponFlags[1] & ScriptFlag))
            return false;
        for (const auto &hand : pm->ps->hands)
            if (hand.state || hand.weaponTime || hand.weaponDelay)
                return false;
        return true;
    }
}

extern "C" bool DW_WeaponInspect_HasClip(const DWInspectPlayerState *ps)
{
    if (!ps || !ps->scriptAnimation || !DW_LocalBackend_IsEnabled())
        return false;
    const char *animation = nullptr;
    return WIR_AnimationName(XAnimNetConstType, ps->scriptAnimation, &animation) &&
        FindAnimation(animation);
}

extern "C" bool DW_WeaponInspect_IsActive(const DWInspectPlayerState *ps)
{
    return ps && DW_LocalBackend_IsEnabled() && OwnedAnimation(ps);
}

extern "C" uint8_t DW_WeaponInspect_UpdateSprint(DWInspectPmove *pm, void *pml)
{
    if (!DW_LocalBackend_IsEnabled() || !pm || !pm->ps || !pml ||
        !OwnedAnimation(pm->ps))
        return WIR_OriginalUpdateSprint(pm, pml);

    auto *ps = pm->ps;
    // Native sprint eligibility rejects the generic scripted-animation flag.
    // Lift only our flag during the actual sprint update, retaining every
    // native input, auto-sprint, stance, movement and stamina restriction.
    // Eligibility probes elsewhere must never cancel an inspection.
    ps->weaponFlags[1] &= ~ScriptFlag;
    const uint8_t result = WIR_OriginalUpdateSprint(pm, pml);
    if (WIR_IsSprinting(ps))
        CancelOwned(pm);
    else
        ps->weaponFlags[1] |= ScriptFlag;
    return result;
}

extern "C" void DW_WeaponInspect_Request(uint32_t local)
{
    // Called by the existing physical-key edge path after its keycatcher and
    // on-foot checks. The existing reliable client-command decoder identifies
    // the sender; the server dispatcher validates its entity and living state.
    // Replay stores one connection pointer; the type byte immediately follows
    // it. Fail closed for another local index instead of indexing that byte.
    if (local != 0 || !DW_LocalBackend_IsEnabled() || !WIR_IsMainThread() ||
        WIR_ConnectionType != 2 || !WIR_IsConnected(local))
        return;
    void *connection = WIR_ClientConnection;
    if (connection)
        WIR_AddReliableCommand(connection, "dw_inspect");
}

extern "C" void DW_WeaponInspect_ServerRequest(int32_t clientNumber, void *playerState)
{
    auto *ps = static_cast<DWInspectPlayerState *>(playerState);
    if (!DW_LocalBackend_IsEnabled() || clientNumber < 0 ||
        uint32_t(clientNumber) >= ClientCount || !ps ||
        ps->clientNumber != clientNumber || ps->movementType != 0)
        return;
    auto &pending = s_pending[clientNumber];
    if (__atomic_exchange_n(&pending.locked, 1u, __ATOMIC_ACQUIRE))
        return;
    __atomic_store_n(&pending.time, WIR_Milliseconds(), __ATOMIC_RELAXED);
    __atomic_store_n(&pending.playerState, reinterpret_cast<uintptr_t>(ps), __ATOMIC_RELEASE);
    __atomic_store_n(&pending.locked, 0u, __ATOMIC_RELEASE);
}

extern "C" uint8_t DW_WeaponInspect_PMove(DWInspectPmove *pm, void *pml)
{
    if (!DW_LocalBackend_IsEnabled() || !pm || !pm->ps || !pml)
        return WIR_OriginalWeapon(pm, pml);
    auto *ps = pm->ps;
    const auto *owned = OwnedAnimation(ps);
    const auto *current = owned ? CurrentAsset(pm) : nullptr;
    if (owned && (!Eligible(pm) || WeaponSelectionChanged(pm) || !current ||
        strcmp(current->animation, owned->animation) ||
        uint32_t(uint32_t(pm->command.serverTime) - uint32_t(ps->scriptStartTime)) >= owned->durationMs))
    {
        CancelOwned(pm);
        owned = nullptr;
    }
    // The accepted server action reaches clients through the existing scripted
    // viewmodel fields in snapshots. There is no speculative local playback;
    // a remote client observes normal reliable-command and snapshot latency.
    const bool requested = TakeRequest(ps);
    if (requested && !owned && CanStart(pm) && !WeaponSelectionChanged(pm))
    {
        const auto *asset = CurrentAsset(pm);
        uint32_t animation = 0;
        if (asset && asset->durationMs &&
            WIR_AnimationIndex(XAnimNetConstType, asset->animation, &animation) && animation)
        {
            // Replay's existing SCRIPTED animation maps to node380, and the
            // existing client tree resolves this type16 index to our real clip.
            // The setter owns state62, animation70, script flag and timers.
            WIR_PlayScripted(pm->weaponMap, ps, animation, pm->command.serverTime,
                static_cast<int32_t>(asset->durationMs), 0);
        }
    }
    return WIR_OriginalWeapon(pm, pml);
}
