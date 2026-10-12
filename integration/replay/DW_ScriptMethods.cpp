#include <stdint.h>
#include <stddef.h>
#include "DW_ScriptMethodBindings.h"

// Target Replay scr_entref_t is passed in one integer register. The engine uses
// only entityNum and classNum; preserve all bits when forwarding a callback.
struct ScriptEntityRef {
    uint32_t entityNum;
    uint8_t classNum;
    uint8_t reserved[3];
};
using ScriptMethodCallback = void (*)(void *, uint64_t);
struct BuiltinMethodDefinition {
    uint32_t id;
    uint32_t padding0;
    ScriptMethodCallback callback;
    uint32_t type;
    uint32_t padding1;
};
struct BuiltinMethodTable {
    const BuiltinMethodDefinition *methods;
    uint64_t count;
};
struct ReplayScriptContext {
    uint8_t prefix[3188];
    uint32_t functionBegin;            // 0xc74
    uint32_t functionEnd;              // 0xc78, exclusive
    uint32_t functionCount;            // 0xc7c
    uint32_t methodBegin;              // 0xc80
    uint32_t methodEnd;                // 0xc84, exclusive
    uint32_t methodCount;              // 0xc88
    uint32_t padding;
    uint64_t *functionTable;           // 0xc90
    ScriptMethodCallback *methodTable; // 0xc98
    uint8_t toThreadState[31088 - 3232];
    uint32_t threadState;
    uint8_t toVmCounter[82952 - 31092];
    uint64_t vmCounter;
    uint8_t toInstance[153632 - 82960];
    uint8_t instance;
};
static_assert(sizeof(ScriptEntityRef) == 8);
static_assert(sizeof(BuiltinMethodDefinition) == 24);
static_assert(offsetof(BuiltinMethodDefinition, callback) == 8);
static_assert(offsetof(BuiltinMethodDefinition, type) == 16);
static_assert(sizeof(BuiltinMethodTable) == 16);
static_assert(offsetof(ReplayScriptContext, functionTable) == 3216);
static_assert(offsetof(ReplayScriptContext, methodTable) == 3224);
static_assert(offsetof(ReplayScriptContext, threadState) == 31088);
static_assert(offsetof(ReplayScriptContext, vmCounter) == 82952);
static_assert(offsetof(ReplayScriptContext, instance) == 153632);

// The build-time registry and baked script operand must derive the same ID.
// Add entries here contiguously; buffer/count/end grow together.
extern "C" void DW_BotStyleWeaponMethod(void *context, uint64_t self);
extern "C" void DW_BotSurvivalAllowedMethod(void *context, uint64_t self);
extern "C" void DW_BotMPClassReadyMethod(void *context, uint64_t self);
static const BuiltinMethodDefinition customMethods[] = {
    {SM_CustomMethodBegin, 0, DW_BotStyleWeaponMethod, 0, 0},
    {SM_CustomMethodBegin + 1, 0, DW_BotSurvivalAllowedMethod, 0, 0},
    {SM_CustomMethodBegin + 2, 0, DW_BotMPClassReadyMethod, 0, 0},
};
static constexpr uint32_t customCount = sizeof(customMethods) / sizeof(customMethods[0]);
static ScriptMethodCallback methodCallbacks[SM_NativeMethodCount + customCount];
static const BuiltinMethodTable customMethodTable{customMethods, customCount};

// Complete original entry + its derived native tail setter. No byte patch and
// no call back through a replaced native target. Non-server behavior is exact.
extern "C" void *DW_ScriptContextInitialize(uint8_t instance) {
    auto *context = static_cast<ReplayScriptContext *>(SM_ContextInstances[instance]);
    context->instance = instance;
    context->threadState = 0;
    context->vmCounter = 0;
    if (instance != 0)
        return nullptr;
    context->functionBegin = SM_FunctionBegin;
    context->functionTable = SM_OriginalFunctionCallbacks;
    context->methodTable = methodCallbacks;
    context->functionEnd = SM_FunctionEnd;
    context->functionCount = SM_FunctionCount;
    context->methodBegin = SM_NativeMethodBegin;
    context->methodEnd = SM_CustomMethodBegin + customCount;
    context->methodCount = SM_NativeMethodCount + customCount;
    return methodCallbacks;
}

// Preserve all 19 native tables, their order and original first-nonzero return.
// The original helper installs numeric descriptors and returns zero on Replay.
extern "C" uint32_t DW_GScriptMPGetMethod(void *, const char **name, uint32_t *type) {
    *type = 0;
    void *context = SM_ServerContext();
    for (const BuiltinMethodTable *table : SM_NativeMethodTables) {
        const uint32_t result = SM_RegisterMethodTable(context, name, type, table);
        if (result != 0)
            return result;
    }
    return SM_RegisterMethodTable(context, name, type, &customMethodTable);
}

// Callback implementation belongs to the bot-style owner. Its safe native ABI:
// 1. entity = SM_GetEntity(self); reject non-bot/non-player receiver by existing
//    native bot/entity facts. The helper preserves native object-error behavior.
// 2. Require SM_GetNumParam(context)==2, then call
//    SM_GetWeaponParam(context, 0, &localWeapon60, &alternate).
//    This copies all 60 bytes and preserves managed weapon alternate mode.
// 3. Apply verified profile attachments to the local copy only; validate using
//    the bot-style owner's native weapon validation.
// 4. SM_AddWeaponParam(context, &localWeapon60, alternate) creates/interns a
//    managed native clone and adds an entity-class10 result with normal VM refs.
// Never return a borrowed Weapon pointer or mutate the shared managed table.
