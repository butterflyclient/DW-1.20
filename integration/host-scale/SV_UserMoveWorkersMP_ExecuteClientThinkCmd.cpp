#include "sv_bot_command_ownership.h"
#include <intrin.h>

namespace
{
    // The producer publishes these entries before native pending's release
    // increment. The consumer clears each entry before releasing its slot.
    // Human commands explicitly publish an empty owner.
    HostScale::BotCommandOwner owners[200][6];
} // namespace

extern "C" void SV_HostBot_StampQueuedCommand(unsigned slot, unsigned entry,
                                              const HostScale::BotCommandOwner *owner)
{
    if (slot < 200 && entry < 6)
        owners[slot][entry] = owner ? *owner : HostScale::BotCommandOwner{};
}

extern "C" bool SV_HostBot_AcceptQueuedCommand(unsigned slot, unsigned entry)
{
    if (slot >= 200 || entry >= 6)
        return false;
    const auto owner = owners[slot][entry];
    owners[slot][entry] = {};
    return !owner.client || HostScale::SameBotCommandOwner(slot, owner);
}

extern "C" void SV_UserMoveWorkersMP_ExecuteClientThinkCmd(const unsigned *commandInfo)
{
    using namespace HostScale;
    SVHS_TimingStartWorker();
    const unsigned slot = *commandInfo;
    auto &queue = static_cast<ThinkQueue *>(SVHS_ThinkQueues)[slot];
    const unsigned entry = queue.readIndex;
    const UserCmd command = queue.commands[entry];
    auto &active = SVHS_InWorkerContext[SVHS_CurrentThreadContext()];
    auto *tlsSlots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
    auto *tls = reinterpret_cast<uint8_t *>(tlsSlots[SVHS_BotTlsIndex]);
    void *previousStatics = Field<void *>(tls, 16);
    active = 1;
    Field<void *>(tls, 16) = nullptr;
    if (SV_HostBot_AcceptQueuedCommand(slot, entry))
        SVHS_ClientThinkInternal(SVHS_Clients[slot], &command);
    active = 0;
    tlsSlots = reinterpret_cast<uintptr_t *>(__readgsqword(0x58));
    tls = reinterpret_cast<uint8_t *>(tlsSlots[SVHS_BotTlsIndex]);
    Field<void *>(tls, 16) = previousStatics;
    queue.readIndex = (queue.readIndex + 1) % 6;
    const unsigned nextSlot = *commandInfo;
    auto &nextQueue = static_cast<ThinkQueue *>(SVHS_ThinkQueues)[nextSlot];
    if (__atomic_fetch_sub(&nextQueue.pending, 1, __ATOMIC_SEQ_CST) > 1)
        SVHS_AddWorker(128, &nextSlot);
    SVHS_TimingEndWorker();
}
