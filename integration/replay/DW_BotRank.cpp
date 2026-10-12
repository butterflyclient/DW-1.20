#include "DW_BotRankBindings.h"
#include "DW_BotStyleProfile.h"
#include "DW_BotStyleSelection.h"
#include "DW_BotBindings.h"
#include "sv_host_scale.h"
#include <stddef.h>

namespace
{
    // Complete prefix through the two fields written by Replay setrank. Other
    // session/player state stays opaque and belongs to the native game.
    struct RankClient
    {
        uint8_t prefix[RK_RankOffset];
        uint16_t rank, prestige;
    };

    static_assert(offsetof(RankClient, rank) == RK_RankOffset);
    static_assert(offsetof(RankClient, prestige) == RK_PrestigeOffset);
    static_assert(sizeof(RankClient) == RK_PrestigeOffset + sizeof(uint16_t));

    bool Apply(HostScale::Entity *entity, unsigned client)
    {
        uint64_t profile = 0;
        if (!DWBot_IsCurrentEntity(client, entity) ||
            !DW_BotPolicy_ProfileSeed(client, &profile))
            return false;
        const auto selected = DWBotStyle::SelectRank(profile);
        if (selected.index > RK_MaxRank)
            return false;
        auto *state = reinterpret_cast<RankClient *>(entity->client);
        state->rank = selected.index;
        state->prestige = 0; // Same non-prestige profile exposed in the lobby.
        return true;
    }
} // namespace

// Called by the existing assigned-team getter before native ClientBegin runs
// CalculateRanks or its first entity script. No per-frame setter is introduced.
extern "C" bool DW_BotRank_Apply(unsigned client)
{
    return client < 200 && RK_Entities && Apply(&RK_Entities[client], client);
}

// Complete original PlayerCmd_SetRank behavior, including validation order and
// native error identities. Only a valid transported DW bot profile replaces the
// successfully parsed rank/prestige after the original writes have completed.
extern "C" uint64_t DW_BotRank_SetRank(void *context, uint64_t self)
{
    HostScale::Entity *entity;
    if ((self >> 32) & 0xff)
    {
        RK_ObjectError(3681, context, "not an entity");
        entity = nullptr; // Native object errors leave the current script frame.
    }
    else
    {
        entity = &RK_Entities[uint32_t(self)];
        if (!entity->client)
            RK_ObjectError(3680, context, RK_Format("entity %i is not a player", uint32_t(self)));
    }
    const uint32_t requested = uint32_t(RK_GetInt(context, 0));
    if (requested > RK_MaxRank)
        return RK_Error(1390,
                        context,
                        RK_Format("'%i' is an illegal rank value.  Must be less than %i.\n",
                                  requested,
                                  RK_MaxRank + 1));
    auto *state = reinterpret_cast<RankClient *>(entity->client);
    state->rank = uint16_t(requested);
    uint32_t result = RK_GetNumParam(context);
    if (result >= 2)
    {
        result = uint32_t(RK_GetInt(context, 1));
        if (result > RK_MaxPrestige)
            return RK_Error(1391,
                            context,
                            RK_Format("'%i' is an illegal prestige value.  Must be less than %i.\n",
                                      result,
                                      RK_MaxPrestige + 1));
        state->prestige = uint16_t(result);
    }
    Apply(entity, uint32_t(self));
    return result;
}
