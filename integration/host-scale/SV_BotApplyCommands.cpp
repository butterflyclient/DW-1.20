#include "sv_host_scale.h"

extern "C" void SV_BotApplyCommands(HostScale::UserCmd *commands)
{
    using namespace HostScale;
    const bool parallel = Enabled() && Population() > 20 && SVHS_WorkersEnabled;
    unsigned queued = 0, serial = 0;
    for (unsigned slot = 0; slot < SVHS_ClientCount; ++slot)
    {
        void *client = SVHS_Clients[slot];
        if (!SVHS_SupportsFeature(2) || Field<int32_t>(client, 214756) != 2)
            continue;
        if (Field<uint8_t>(client, 8) < 5)
            continue;
        auto *entity = Field<Entity *>(client, 280);
        auto *player = entity->client;
        if (Field<int32_t>(player, 21368) == 2)
            SVHS_AcknowledgeBotCommands(client);
        // All original live predicates are checked after acknowledgement.
        if (Field<uint8_t>(client, 8) < 5)
            continue;
        entity = Field<Entity *>(client, 280);
        player = entity->client;
        if (Field<int32_t>(player, 21368) == 2 && Field<int32_t>(player, 21372) == 0 &&
            Field<int32_t>(player, 448) == entity->number)
        {
            if (commands[slot].serverTime <= Field<int32_t>(client, 28))
                continue;
            if (parallel && SV_UserMoveWorkersMP_TryQueueClientThinkCmd(slot, &commands[slot]))
                ++queued;
            else
            {
                SVHS_ClientThink(client, &commands[slot]);
                ++serial;
            }
        }
        else if (Field<int32_t>(player, 21368) == 2 && Field<int32_t>(player, 21372) == 2)
        {
            Field<uint64_t>(client, 16) = commands[slot].buttons;
            Field<int32_t>(client, 28) = commands[slot].serverTime;
            Field<int32_t>(client, 32) = commands[slot].commandTime;
            if (Field<uint8_t>(client, 8) == 5)
            {
                Field<uint64_t>(player, 21640) = Field<uint64_t>(player, 21376);
                SVHS_GetUsercmd(slot, player + 21376);
                player = Field<Entity *>(client, 280)->client;
                Field<uint64_t>(player, 24032) = Field<uint64_t>(player, 24024);
                Field<uint64_t>(player, 24024) = Field<uint64_t>(player, 21376);
                Field<uint64_t>(player, 24048) |=
                    Field<uint64_t>(player, 24024) & ~Field<uint64_t>(player, 24032);
            }
        }
    }
    // Do not defer this fence to the caller: it resets the skeleton cache and
    // updates agents immediately after this routine returns. Queue entries own
    // full command copies, and every worker must finish before those consumers.
    if (queued)
        SVHS_FinishClientThinkCmds();
    RecordMovement(queued, serial);
}
