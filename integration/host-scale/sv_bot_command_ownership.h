#pragma once
#include "sv_host_scale.h"

extern "C" bool DW_LocalBackend_IsEnabled();

namespace HostScale
{
    // Native SvClientMP embeds bot_data_t at 1368. This view covers the entire
    // prefix used for ownership, keeping unidentified fields opaque.
    struct CommandBotInfo
    {
        Entity *entity;
        Sentient *sentient;
        uint8_t opaque16[432];
        uint8_t *player;
    };

    static_assert(offsetof(CommandBotInfo, player) == 448);
    static_assert(sizeof(CommandBotInfo) == 456);

    struct BotCommandOwner
    {
        void *client;
        Entity *entity;
        uint8_t *player;
        Sentient *sentient;
        int32_t sessionState;
    };

    inline bool CurrentBotCommandOwner(unsigned slot, BotCommandOwner &owner)
    {
        owner = {};
        if (SVHS_ClientCount > 200 || slot >= SVHS_ClientCount)
            return false;
        void *client = SVHS_Clients[slot];
        if (!client || Field<int32_t>(client, 214756) != 2 || Field<uint8_t>(client, 8) < 5)
            return false;
        auto *info = reinterpret_cast<CommandBotInfo *>(static_cast<uint8_t *>(client) + 1368);
        auto *entity = Field<Entity *>(client, 280);
        if (!entity || entity != info->entity || entity->number != int(slot) || !entity->client ||
            entity->client != info->player || !entity->sentient ||
            entity->sentient != info->sentient ||
            Field<int32_t>(entity->client, 448) != int(slot) ||
            Field<int32_t>(entity->client, 21368) != 2 || !SVHS_IsBotEntity(entity))
            return false;
        owner = {client, entity, entity->client, entity->sentient,
                 Field<int32_t>(entity->client, 21372)};
        return true;
    }

    inline bool SameBotCommandOwner(unsigned slot, const BotCommandOwner &owner)
    {
        BotCommandOwner current;
        return CurrentBotCommandOwner(slot, current) && current.client == owner.client &&
               current.entity == owner.entity && current.player == owner.player &&
               current.sentient == owner.sentient && current.sessionState == owner.sessionState;
    }
} // namespace HostScale

extern "C"
{
    void SV_HostBot_StampQueuedCommand(unsigned, unsigned, const HostScale::BotCommandOwner *);
    bool SV_HostBot_AcceptQueuedCommand(unsigned, unsigned);
    void SV_UserMoveWorkersMP_ExecuteClientThinkCmd(const unsigned *);
}
