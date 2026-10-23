#include "replay_dvar.h"

extern "C" {
bool DCA_PlayingBR();
uint64_t DCA_CycleWeaponNative(unsigned, void *, void *, bool);
uint64_t DCA_CycleWeaponBR(unsigned, void *, void *, bool);
}

namespace {
constexpr dvar_t ArmorInputPolicy() {
    dvar_t value{};
    value.current.enabled = true;
    return value;
}
constexpr dvar_t BrArmorInput = ArmorInputPolicy();
}

// Only the BR copy of the native input routine reads this immutable value.
// The registered dvar and the server's armor eligibility checks stay native.
extern "C" const dvar_t *const DCA_ArmorInput = &BrArmorInput;

extern "C" uint64_t DW_ControllerArmor_CycleWeapon(
    unsigned localClient, void *button, void *command, bool forward) {
    if (DCA_PlayingBR())
        return DCA_CycleWeaponBR(localClient, button, command, forward);
    return DCA_CycleWeaponNative(localClient, button, command, forward);
}
