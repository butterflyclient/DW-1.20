#include "../integration/host-scale/sv_bot_command_ownership.h"
#include <intrin.h>

namespace
{
    alignas(16) uint8_t client[321192];
    uint8_t player[64496];
    HostScale::Entity entity;
    HostScale::Sentient sentient;
    HostScale::ThinkQueue queue;
    bool enabled = true;
    bool parallel = false;
    unsigned thinkCalls, preThinkCalls, scheduled, starts, ends, acknowledgements;
    unsigned mutation, mutationAt;
    uint64_t observedButtons;
    unsigned result[14];
} // namespace

extern "C"
{
    // Isolate the native GS-based TLS access to this offline harness's storage.
    // No engine, Windows, or C runtime boundary runs while the slot is replaced.
    void __writegsqword(unsigned long offset, uint64_t value)
    {
        (void)offset;
        __asm__ volatile("movq %0, %%gs:0x58" : : "r"(value) : "memory");
    }

    uint32_t SVHS_ClientCount = 1;
    void *SVHS_Clients[200]{};
    void *SVHS_ThinkQueues = &queue;
    uint8_t SVHS_WorkersEnabled = 1;
    uint32_t SVHS_BotTlsIndex = 0;
    uint32_t SVHS_InWorkerContext[28]{};

    void *memcpy(void *destination, const void *source, size_t size)
    {
        auto *out = static_cast<uint8_t *>(destination);
        const auto *in = static_cast<const uint8_t *>(source);
        for (size_t i = 0; i < size; ++i)
            out[i] = in[i];
        return destination;
    }

    void *memset(void *destination, int value, size_t size)
    {
        auto *out = static_cast<uint8_t *>(destination);
        for (size_t i = 0; i < size; ++i)
            out[i] = uint8_t(value);
        return destination;
    }

    bool DW_LocalBackend_IsEnabled()
    {
        return enabled;
    }

    bool SVHS_SupportsFeature(unsigned)
    {
        return true;
    }

    bool SVHS_IsBotEntity(const void *)
    {
        return HostScale::Field<int32_t>(client, 214756) == 2;
    }

    void MutateOwner(unsigned kind)
    {
        using namespace HostScale;
        switch (kind)
        {
        case 1:
            Field<int32_t>(client, 214756) = 0;
            break;
        case 2:
            Field<Entity *>(client, 280) = nullptr;
            break;
        case 3:
            entity.client = nullptr;
            break;
        case 4:
            entity.number = 1;
            break;
        case 5:
            Field<int32_t>(player, 448) = 1;
            break;
        case 6:
            reinterpret_cast<CommandBotInfo *>(client + 1368)->entity = nullptr;
            break;
        case 7:
            reinterpret_cast<CommandBotInfo *>(client + 1368)->player = nullptr;
            break;
        case 8:
            entity.sentient = nullptr;
            break;
        case 9:
            Field<uint8_t>(client, 8) = 3;
            break;
        case 10:
            Field<int32_t>(player, 21368) = 0;
            break;
        case 11:
            Field<int32_t>(player, 21372) = 2;
            break;
        case 12:
            SVHS_Clients[0] = nullptr;
            break;
        }
    }

    void SVHS_AcknowledgeBotCommands(void *)
    {
        ++acknowledgements;
        if (mutationAt == 1)
            MutateOwner(mutation);
    }

    void SVHS_UserMoveBegin()
    {
    }

    bool SVHS_ClientPreThink(void *, const void *)
    {
        ++preThinkCalls;
        if (mutationAt == 2)
            MutateOwner(mutation);
        return true;
    }

    void SVHS_ClientThinkInternal(void *, const void *command)
    {
        ++thinkCalls;
        observedButtons = static_cast<const HostScale::UserCmd *>(command)->buttons;
        HostScale::Field<uint64_t>(client, 16) = observedButtons;
    }

    void SVHS_ClientThink(void *current, const void *command)
    {
        SVHS_ClientThinkInternal(current, command);
    }

    void SVHS_GetUsercmd(unsigned, void *)
    {
    }

    void SVHS_FinishClientThinkCmds()
    {
    }

    void SVHS_AddWorker(unsigned, const void *)
    {
        ++scheduled;
    }

    void SVHS_WaitWorkerType(unsigned)
    {
        queue.pending = 0;
    }

    void SVHS_Sleep(unsigned)
    {
        queue.pending = 0;
    }

    unsigned SVHS_CurrentThreadContext()
    {
        return 3;
    }

    void SVHS_TimingStartWorker()
    {
        ++starts;
    }

    void SVHS_TimingEndWorker()
    {
        ++ends;
    }

    __declspec(dllexport) const unsigned *OwnershipTest(unsigned scenario, unsigned change,
                                                        unsigned count, unsigned tlsIndex)
    {
        using namespace HostScale;
        memset(client, 0, sizeof(client));
        memset(player, 0, sizeof(player));
        memset(&entity, 0, sizeof(entity));
        memset(&sentient, 0, sizeof(sentient));
        memset(&queue, 0, sizeof(queue));
        memset(SVHS_InWorkerContext, 0, sizeof(SVHS_InWorkerContext));
        for (unsigned i = 0; i < 6; ++i)
            SV_HostBot_StampQueuedCommand(0, i, nullptr);
        SVHS_Clients[0] = client;
        SVHS_ClientCount = 1;
        SVHS_WorkersEnabled = 1;
        (void)tlsIndex;
        SVHS_BotTlsIndex = 0;
        alignas(8) uint8_t tls[32]{};
        Field<uint64_t>(tls, 16) = 0xabcdef0123456789;
        uintptr_t slots[1]{reinterpret_cast<uintptr_t>(tls)};
        const uintptr_t previousSlots = __readgsqword(0x58);
        __writegsqword(0x58, reinterpret_cast<uintptr_t>(slots));
        enabled = true;
        parallel = scenario == 5;
        thinkCalls = preThinkCalls = scheduled = starts = ends = acknowledgements = 0;
        observedButtons = 0;
        mutation = change;
        mutationAt = 0;
        Field<int32_t>(client, 214756) = 2;
        Field<uint8_t>(client, 8) = 5;
        Field<Entity *>(client, 280) = &entity;
        entity.client = player;
        entity.sentient = &sentient;
        Field<int32_t>(player, 21368) = 2;
        auto *info = reinterpret_cast<CommandBotInfo *>(client + 1368);
        info->entity = &entity;
        info->player = player;
        info->sentient = &sentient;
        UserCmd command{};
        command.buttons = 0x123456789abc;
        command.serverTime = 1000;
        command.commandTime = 999;
        Field<uint64_t>(client, 16) = 0xdeadbeef98765432;
        unsigned slot = 0;
        if (scenario == 1)
            Field<int32_t>(client, 214756) = 0;
        if (scenario == 2)
            enabled = false;
        if (scenario == 4 || scenario == 5)
        {
            mutationAt = scenario == 4 ? 1 : 2;
            SV_BotApplyCommands(&command);
        }
        else
        {
            for (unsigned i = 0; i < count; ++i)
            {
                command.buttons += i;
                SV_UserMoveWorkersMP_TryQueueClientThinkCmd(slot, &command);
            }
            if (scenario == 3)
                MutateOwner(change);
            if (scenario == 6)
            {
                // Native queue reset followed by a human entry must replace
                // the old sidecar stamp, including a reused ring index.
                queue.pending = queue.readIndex = queue.writeIndex = 0;
                MutateOwner(1);
                SV_UserMoveWorkersMP_TryQueueClientThinkCmd(slot, &command);
                count = 1;
            }
            for (unsigned i = 0; i < count; ++i)
                SV_UserMoveWorkersMP_ExecuteClientThinkCmd(&slot);
        }
        __writegsqword(0x58, previousSlots);
        result[12] = Field<uint64_t>(tls, 16) == 0xabcdef0123456789;
        result[0] = thinkCalls;
        result[13] = Field<uint64_t>(client, 16) == 0xdeadbeef98765432;
        result[1] = preThinkCalls;
        result[2] = scheduled;
        result[3] = starts;
        result[4] = ends;
        result[5] = queue.pending;
        result[6] = queue.readIndex;
        result[7] = queue.writeIndex;
        result[8] = SVHS_InWorkerContext[3];
        result[9] = unsigned(observedButtons);
        result[10] = unsigned(observedButtons >> 32);
        result[11] = acknowledgements;
        return result;
    }
}

namespace HostScale
{
    bool Enabled()
    {
        return parallel;
    }

    unsigned Population()
    {
        return parallel ? 21 : 1;
    }

    void RecordMovement(unsigned, unsigned)
    {
    }

    void RecordBackpressure()
    {
    }
} // namespace HostScale
