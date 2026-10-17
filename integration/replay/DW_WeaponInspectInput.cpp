#include "DW_WeaponInspectInput.h"
#include "DW_WeaponInspectInputBindings.h"
#include "replay_dvar.h"
#include <string.h>

extern "C" bool DW_LocalBackend_IsEnabled();

namespace
{
    constexpr uint32_t ClientCount = 2;
    constexpr uint32_t KeyCount = 222;
    constexpr uint32_t ClientUiStride = 440;
    constexpr uint32_t ClientBindingsStride = 18135;
    constexpr uint8_t OnFootContext = 2;
    constexpr char Command[] = "dw_inspect";
    constexpr const char *KeyNames[2] = {
        "replay_dw_inspectPrimaryKey", "replay_dw_inspectSecondaryKey"
    };

    struct Capture
    {
        void *vm;
        uint32_t controller;
        uint8_t slot;
        bool active;
    };

    dvar_t *s_keys[2];
    Capture s_capture[ClientCount];
    bool s_down[ClientCount][2];

    bool IsOurCommand(void *vm)
    {
        if (!DW_LocalBackend_IsEnabled() || WI_LuaTop(vm) != 4 || WI_LuaType(vm, 3) != 4)
            return false;
        const char *command = WI_LuaString(vm, 3, nullptr);
        return command && strcmp(command, Command) == 0;
    }

    bool ReadArguments(void *vm, uint32_t &local, uint32_t &slot)
    {
        if (WI_LuaType(vm, 1) != 3 || WI_LuaType(vm, 2) != 4 || WI_LuaType(vm, 4) != 3)
            return false;
        // Replay's keyboard binding getters accept controller zero only.
        const int64_t controller = WI_LuaInteger(vm, 1);
        const int64_t index = WI_LuaInteger(vm, 4);
        const char *context = WI_LuaString(vm, 2, nullptr);
        if (controller != 0 || index < 0 || index > 1 || !context || strcmp(context, "ONFOOT"))
            return false;
        local = WI_ClientFromController(0);
        slot = static_cast<uint32_t>(index);
        return local < ClientCount;
    }

    int InvalidArguments(void *vm)
    {
        return WI_LuaError(vm, "dw_inspect requires controller 0, context ONFOOT and slot 0 or 1");
    }

    void SetKey(uint32_t slot, uint32_t key)
    {
        if (!s_keys[slot])
            return;
        DvarValue value{};
        value.integer = static_cast<int32_t>(key);
        Dvar_SetVariant(s_keys[slot], &value, 0);
    }

    uint32_t GetKey(uint32_t slot)
    {
        const int32_t key = s_keys[slot] ? s_keys[slot]->current.integer : 0;
        return key > 0 && key < static_cast<int32_t>(KeyCount) ? static_cast<uint32_t>(key) : 0;
    }

    void KeyLabel(uint32_t controller, uint32_t key, char (&buffer)[256])
    {
        buffer[0] = 0;
        if (key)
        {
            const char *name = WI_KeyName(controller, static_cast<int32_t>(key));
            if (name)
                WI_FormatKey(buffer, sizeof(buffer), name, false);
        }
    }

    void StopCapture(uint32_t local)
    {
        if (s_capture[local].active)
            WI_Waiting[local] = 0;
        s_capture[local] = {};
    }

    void KeyBoundEvent(uint32_t local, uint32_t controller, uint32_t key,
                       bool cancelled, bool invalid)
    {
        void *vm = WI_LuaVM;
        if (!WI_BeginEvent(local, "key_bound", vm))
            return;
        WI_TableInt("controller", controller, vm);
        WI_TableBool("immediate", true, vm);
        WI_TableBool("cancelBinding", cancelled, vm);
        if (invalid)
        {
            WI_TableBool("invalidBinding", true, vm);
            char label[256]{};
            KeyLabel(controller, key, label);
            WI_LuaPushString(vm, label);
            WI_LuaSetField(vm, -2, "buttonName");
        }
        // The stock menu's conflict banner expects an array, even when empty.
        WI_LuaCreateTable(vm, 0, 0);
        WI_LuaSetField(vm, -2, "unboundCommands");
        WI_EndEvent(vm);
    }

    bool NativeConflict(uint32_t local, uint32_t key)
    {
        const uint8_t *bindings = WI_Bindings + ClientBindingsStride * local;
        // Check all supported on-foot modes, including inherited COMMON and
        // GLOBAL assignments. No shipped action is unbound or reassigned.
        constexpr uint8_t contexts[] = { 0, 1, 2, 13 };
        for (uint8_t context : contexts)
            for (uint32_t action = 1; action < 255; ++action)
                for (uint8_t slot = 0; slot < 2; ++slot)
                    if (WI_BoundKey(bindings, context, static_cast<uint8_t>(action), slot, true) == key)
                        return true;
        return false;
    }

    bool ReservedKey(uint32_t key)
    {
        return !key || key >= KeyCount || key == 96 || WI_IsGamepad(static_cast<uint8_t>(key));
    }

    bool GameplayInput(uint32_t local)
    {
        if (WI_KeyCatchers[ClientUiStride * local / sizeof(uint32_t)] != 0 ||
            !WI_Connected(local) || WI_Waiting[local])
            return false;
        const uint8_t context = WI_ActiveContext[local];
        return context == 0 || context == 1 || context == 2 || context == 13;
    }
}

extern "C" void DW_WeaponInspectInput_Init()
{
    if (s_keys[0] || !DW_LocalBackend_IsEnabled() || !WI_IsMainThread())
        return;
    Dvar_BeginPermanentRegistration();
    s_keys[0] = Dvar_RegisterInt(KeyNames[0], 0, 0, KeyCount - 1, 1,
        "Primary weapon inspection key; zero is unbound.");
    s_keys[1] = Dvar_RegisterInt(KeyNames[1], 0, 0, KeyCount - 1, 1,
        "Secondary weapon inspection key; zero is unbound.");
    Dvar_EndPermanentRegistration();
}

extern "C" int DW_WeaponInspectInput_Capture(void *vm)
{
    if (!IsOurCommand(vm))
    {
        // A stock binding operation supersedes any pending custom capture.
        for (uint32_t local = 0; local < ClientCount; ++local)
            StopCapture(local);
        return WI_OriginalCapture(vm);
    }
    uint32_t local, slot;
    if (!ReadArguments(vm, local, slot))
        return InvalidArguments(vm);
    DW_WeaponInspectInput_Init();
    if (!s_keys[slot])
        return WI_LuaError(vm, "Weapon inspection keys are not initialized");
    s_capture[local] = { vm, 0, static_cast<uint8_t>(slot), true };
    // The native waiting bit routes physical keys into HandleKeyBind. Command
    // zero is never dispatched: our owner handles this capture before stock.
    WI_SetWaiting(local, OnFootContext, 0, static_cast<uint8_t>(slot));
    return 0;
}

extern "C" int DW_WeaponInspectInput_Unbind(void *vm)
{
    if (!IsOurCommand(vm))
        return WI_OriginalUnbind(vm);
    uint32_t local, slot;
    if (!ReadArguments(vm, local, slot))
        return InvalidArguments(vm);
    SetKey(slot, 0);
    return 0;
}

extern "C" int DW_WeaponInspectInput_Reset(void *vm)
{
    if (!IsOurCommand(vm))
        return WI_OriginalReset(vm);
    uint32_t local, slot;
    if (!ReadArguments(vm, local, slot))
        return InvalidArguments(vm);
    SetKey(slot, 0);
    return 0;
}

extern "C" int DW_WeaponInspectInput_GetDefault(void *vm)
{
    if (!IsOurCommand(vm))
        return WI_OriginalGetDefault(vm);
    uint32_t local, slot;
    if (!ReadArguments(vm, local, slot))
        return InvalidArguments(vm);
    WI_LuaPushString(vm, "");
    return 1;
}

extern "C" int DW_WeaponInspectInput_GetBound(void *vm)
{
    if (!IsOurCommand(vm))
        return WI_OriginalGetBound(vm);
    uint32_t local, slot;
    if (!ReadArguments(vm, local, slot))
        return InvalidArguments(vm);
    DW_WeaponInspectInput_Init();
    char label[256]{};
    KeyLabel(0, GetKey(slot), label);
    WI_LuaPushString(vm, label);
    return 1;
}

extern "C" bool DW_WeaponInspectInput_HandleKey(uint32_t local, uint32_t key)
{
    if (local >= ClientCount || !s_capture[local].active)
        return WI_OriginalHandleKey(local, key);
    if (!DW_LocalBackend_IsEnabled() || !WI_Waiting[local] ||
        s_capture[local].vm != WI_LuaVM)
    {
        StopCapture(local);
        return true;
    }
    const Capture capture = s_capture[local];
    if (key == 27)
    {
        StopCapture(local);
        KeyBoundEvent(local, capture.controller, key, true, false);
        return true;
    }
    // Match stock behavior: gamepad input does not complete keyboard capture.
    if (key < KeyCount && WI_IsGamepad(static_cast<uint8_t>(key)))
        return true;
    const uint32_t other = GetKey(capture.slot ^ 1);
    if (ReservedKey(key) || key == other || NativeConflict(local, key))
    {
        KeyBoundEvent(local, capture.controller, key, false, true);
        return true;
    }
    SetKey(capture.slot, key);
    StopCapture(local);
    KeyBoundEvent(local, capture.controller, key, false, false);
    return true;
}

extern "C" void DW_WeaponInspectInput_Frame()
{
    if (!WI_IsMainThread())
        return;
    DW_WeaponInspectInput_Init();
    if (!DW_LocalBackend_IsEnabled() || !s_keys[0])
        return;
    const uint32_t local = WI_ClientFromController(0);
    if (local >= ClientCount)
        return;
    if (s_capture[local].active &&
        (s_capture[local].vm != WI_LuaVM || !WI_Waiting[local]))
        StopCapture(local);
    bool pressed = false;
    for (uint32_t slot = 0; slot < 2; ++slot)
    {
        const uint32_t key = GetKey(slot);
        const bool down = key && WI_KeyDown(local, static_cast<int32_t>(key));
        const bool edge = down && !s_down[local][slot];
        // Track physical state even while a menu owns input. Closing a menu
        // with an already held inspection key must not start an animation.
        s_down[local][slot] = down;
        pressed |= edge && !ReservedKey(key) && !NativeConflict(local, key);
    }
    if (pressed && !s_capture[local].active && GameplayInput(local))
        DW_WeaponInspect_Request(local);
}
