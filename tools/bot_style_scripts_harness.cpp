// Offline harness for the compiled whole native ScriptFile wrapper.
#include "../integration/replay/DW_BotStyleScripts.cpp"
namespace
{
DWBotStyleScriptFile asset{};
int typeSeen, allowSeen, findCalls, defaultCalls, processCalls;
const char *nameSeen;
void *contextSeen;
int defaultResult;
} // namespace
extern "C" DWBotStyleScriptFile *DWBS_FindAsset(int type, const char *name, int allow)
{
    ++findCalls;
    typeSeen = type;
    nameSeen = name;
    allowSeen = allow;
    return &asset;
}
extern "C" int DWBS_IsDefaultAsset(int type, const char *name)
{
    ++defaultCalls;
    if (type != typeSeen || name != nameSeen)
        return 1;
    return defaultResult;
}
extern "C" void DWBS_ProcessScriptFile(void *context, DWBotStyleScriptFile *file)
{
    ++processCalls;
    contextSeen = context;
    if (file != &asset)
        processCalls = -1000;
}
extern "C" __declspec(dllexport) int Test_Run()
{
    int context{};
    const char name[] = "scripts/mp/bots/bots_gametype_br.gsc";
    defaultResult = 0;
    DW_BotStyle_ProcessScriptFile(&context, name);
    if (findCalls != 1 || defaultCalls != 1 || processCalls != 1 || typeSeen != 52 ||
        allowSeen != 1 || nameSeen != name || contextSeen != &context)
        return __LINE__;
    defaultResult = 1;
    DW_BotStyle_ProcessScriptFile(&context, name);
    if (findCalls != 2 || defaultCalls != 2 || processCalls != 1)
        return __LINE__;
    const auto *package = DW_BotStyleScripts_GetPackage();
    if (!package || !package->zoneName || package->fastfileBytes < 0x94 ||
        package->patchBytes != 0x148)
        return __LINE__;
    if (package->fastfile[0] != 'I' || package->patch[0] != 'I')
        return __LINE__;
    return 0;
}
