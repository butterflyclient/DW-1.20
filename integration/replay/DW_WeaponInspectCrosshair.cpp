#include "DW_WeaponInspectCrosshair.h"
#include "DW_WeaponInspectCrosshairBindings.h"

extern "C" bool DW_LocalBackend_IsEnabled();
extern "C" bool DW_WeaponInspect_IsActive(const DWInspectPlayerState *playerState);

extern "C" bool DW_WeaponInspectCrosshair_Allowed(
    uint32_t localClient, const DWInspectPlayerState *viewedPlayerState)
{
    // Keep every native HUD, spectator, killcam, input and weapon rule. Both
    // native callers supply the currently viewed predicted playerState; it
    // must not be replaced with the last requester or a server player slot.
    const bool allowed = WIC_OriginalAllowed(localClient, viewedPlayerState);
    if (!allowed || !DW_LocalBackend_IsEnabled() || !viewedPlayerState)
        return allowed;

    // Later native inspection reveals its crosshair for the final 800 ms.
    // Ownership checks belong to the inspection runtime: SCRIPTED62 alone is
    // also used by unrelated native animations and must not hide their UI.
    if (DW_WeaponInspect_IsActive(viewedPlayerState) &&
        viewedPlayerState->hands[0].weaponTime > 800)
        return false;
    return allowed;
}
