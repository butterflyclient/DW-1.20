#include "DW_BotStyleScriptBindings.h"
#include "DW_BotStyleScriptPackage.h"
#include <stddef.h>
#include <stdint.h>

// The generated FF owns three complete ScriptFile assets. The ordinary native
// zone loader allocates their bytecode in Replay's DB script pool. Embedded
// resource bytes are never handed directly to ProcessScriptFile.
struct DWBotStyleScriptFile
{
    const char *name;
    int32_t compressedLen;
    int32_t sourceLen;
    int32_t bytecodeLen;
    uint32_t reserved;
    uint8_t *compressedSource;
    uint8_t *bytecode;
};
static_assert(sizeof(DWBotStyleScriptFile) == 40);
static_assert(offsetof(DWBotStyleScriptFile, compressedLen) == 8);
static_assert(offsetof(DWBotStyleScriptFile, sourceLen) == 12);
static_assert(offsetof(DWBotStyleScriptFile, bytecodeLen) == 16);
static_assert(offsetof(DWBotStyleScriptFile, reserved) == 20);
static_assert(offsetof(DWBotStyleScriptFile, compressedSource) == 24);
static_assert(offsetof(DWBotStyleScriptFile, bytecode) == 32);

extern "C"
{
    DWBotStyleScriptFile *DWBS_FindAsset(int, const char *, int);
    int DWBS_IsDefaultAsset(int, const char *);
    void DWBS_ProcessScriptFile(void *, DWBotStyleScriptFile *);
}

// Complete original ScriptFile lookup/default path. A loaded style overlay is
// selected by the ordinary XAsset registry, retaining native script-pool and
// map-unload ownership. This function creates no substitute opcode storage.
extern "C" void DW_BotStyle_ProcessScriptFile(void *context, const char *name)
{
    DWBotStyleScriptFile *file = DWBS_FindAsset(52, name, 1);
    if (!DWBS_IsDefaultAsset(52, name))
        DWBS_ProcessScriptFile(context, file);
}

// The updater/startup asset owner stages this exact FF/FP pair before loading
// its zone through the native DB loader, ahead of native script compilation.
extern "C" const DWBotStyleScriptPackage *DW_BotStyleScripts_GetPackage()
{
    return &DWBotStyleScripts::Package;
}
