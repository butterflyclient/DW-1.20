#include "DW_BotRankBindings.h"
#include "DW_BotStyleSelection.h"
#include "sv_host_scale.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static HostScale::Entity entities[200];
static unsigned char clientState[22200];
extern "C" HostScale::Entity *RK_Entities = entities;
static int arguments[2];
static unsigned count, error, trace;
static uint64_t profile;
static bool mapped;
static uint64_t results[7];
static char message[256];

extern "C" bool DW_BotPolicy_ProfileSeed(unsigned client, uint64_t *seed)
{
    if (!mapped || client != 7 || !seed)
        return false;
    *seed = profile;
    return true;
}

extern "C" int32_t RK_GetInt(void *, uint32_t n)
{
    trace = trace * 10 + (n ? 6 : 3);
    return arguments[n];
}

extern "C" uint32_t RK_GetNumParam(void *)
{
    trace = trace * 10 + 4;
    return count;
}

extern "C" const char *RK_Format(const char *format, ...)
{
    trace = trace * 10 + 1;
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    return message;
}

extern "C" uint64_t RK_Error(uint32_t code, void *, const char *)
{
    trace = trace * 10 + 5;
    error = code;
    return 0xABC;
}

extern "C" void RK_ObjectError(uint32_t code, void *, const char *)
{
    trace = trace * 10 + 2;
    error = code;
    throw code; // Models native VM frame exit; never returns into a null entity.
}

extern "C" uint64_t DW_BotRank_SetRank(void *, uint64_t);
extern "C" bool DW_BotRank_Apply(unsigned);

extern "C" __declspec(dllexport) void Test_Case(unsigned cls,
                                                unsigned hasClient,
                                                unsigned isMapped,
                                                unsigned argc,
                                                int rank,
                                                int prestige,
                                                uint64_t seed)
{
    memset(entities, 0, sizeof(entities));
    memset(clientState, 0, sizeof(clientState));
    entities[7].client = hasClient ? clientState : nullptr;
    *reinterpret_cast<uint16_t *>(clientState + RK_RankOffset) = 91;
    *reinterpret_cast<uint16_t *>(clientState + RK_PrestigeOffset) = 9;
    count = argc;
    arguments[0] = rank;
    arguments[1] = prestige;
    mapped = isMapped != 0;
    profile = seed;
    error = trace = 0;
    uint64_t value = 0;
    try
    {
        value = DW_BotRank_SetRank(nullptr, 7 | (uint64_t(cls) << 32));
    }
    catch (unsigned)
    {
    }
    results[0] = *reinterpret_cast<uint16_t *>(clientState + RK_RankOffset);
    results[1] = *reinterpret_cast<uint16_t *>(clientState + RK_PrestigeOffset);
    results[2] = value;
    results[3] = error;
    results[4] = trace;
    results[5] = DWBotStyle::SelectRank(seed).index;
    results[6] = static_cast<unsigned>(entities[7].health);
}

extern "C" __declspec(dllexport) uint64_t Test_Result(unsigned index)
{
    return results[index];
}

extern "C" __declspec(dllexport) unsigned Test_PreScript(uint64_t seed)
{
    memset(entities, 0, sizeof(entities));
    memset(clientState, 0x5A, sizeof(clientState));
    entities[7].client = clientState;
    profile = seed;
    mapped = true;
    if (!DW_BotRank_Apply(7) || DW_BotRank_Apply(200) || DW_BotRank_Apply(6))
        return 1;
    if (*reinterpret_cast<uint16_t *>(clientState + RK_RankOffset) !=
            DWBotStyle::SelectRank(seed).index ||
        *reinterpret_cast<uint16_t *>(clientState + RK_PrestigeOffset) != 0)
        return 2;
    for (unsigned i = 0; i < sizeof(clientState); ++i)
        if ((i < RK_RankOffset || i >= RK_PrestigeOffset + 2) && clientState[i] != 0x5A)
            return 3;
    return 0;
}
