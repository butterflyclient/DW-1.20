#include "sv_bot_command_ownership.h"

extern "C" bool SV_UserMoveWorkersMP_TryQueueClientThinkCmd(
    unsigned clientIndex, const HostScale::UserCmd *command)
{
    using namespace HostScale;
    if (!SVHS_WorkersEnabled)
        return false;
    BotCommandOwner owner;
    const bool botCommand = DW_LocalBackend_IsEnabled() && clientIndex < 200 &&
        clientIndex < SVHS_ClientCount && SVHS_Clients[clientIndex] &&
        Field<int32_t>(SVHS_Clients[clientIndex], 214756) == 2;
    if (botCommand && !CurrentBotCommandOwner(clientIndex, owner))
        return true;
    SVHS_UserMoveBegin();
    if (!SVHS_ClientPreThink(SVHS_Clients[clientIndex], command))
        return true;
    auto &queue = static_cast<ThinkQueue *>(SVHS_ThinkQueues)[clientIndex];
    while (uint64_t(int64_t(__atomic_load_n(&queue.pending, __ATOMIC_ACQUIRE))) >= 6)
    {
        if (Enabled() && Population() > 20)
        {
            // Native queue drain honors worker eligibility and dependency
            // ordering. It avoids repeated 1ms sleeps under burst input load.
            RecordBackpressure();
            SVHS_WaitWorkerType(128);
        }
        else
            SVHS_Sleep(1);
    }
    if (botCommand && !SameBotCommandOwner(clientIndex, owner))
        return true;
    queue.commands[queue.writeIndex] = *command;
    SV_HostBot_StampQueuedCommand(clientIndex, queue.writeIndex,
                                botCommand ? &owner : nullptr);
    queue.writeIndex = (queue.writeIndex + 1) % 6;
    if (__atomic_add_fetch(&queue.pending, 1, __ATOMIC_SEQ_CST) == 1)
        SVHS_AddWorker(128, &clientIndex);
    return true;
}
