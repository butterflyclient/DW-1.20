#include "sv_host_navigation.h"

namespace
{
    using namespace HostScale;

    struct BotDecision
    {
        UserCmd command;
        void *client, *player;
        int32_t thoughtTime;
        int32_t health;
        uint16_t target;
        bool valid;
    };
    BotDecision s_decisions[200]{};
    struct HumanObserver
    {
        Vec3 origin;
        uint16_t targetHandle;
    };
    HumanObserver s_observers[200]{};
    unsigned s_observerCount;

    void GatherHumanObservers()
    {
        // Snapshot observers once per server frame, rather than scanning the
        // complete client table for every bot decision. Movement runs afterward.
        s_observerCount = 0;
        for (unsigned slot = 0; slot < SVHS_ClientCount && slot < 200; ++slot)
        {
            void *client = SVHS_Clients[slot];
            if (!client || Field<uint8_t>(client, 8) < 5 || Field<int32_t>(client, 214756) == 2)
                continue;
            const auto *entity = Field<Entity *>(client, 280);
            if (entity && entity->client && entity->health > 0)
                s_observers[s_observerCount++] = {entity->origin, uint16_t(entity->number + 1)};
        }
    }

    unsigned DecisionInterval(const Entity *entity, uint16_t target, unsigned population)
    {
        float distanceSquared = 3.402823466e38f;
        for (unsigned i = 0; i < s_observerCount; ++i)
        {
            const auto &observer = s_observers[i];
            if (target && target == observer.targetHandle)
                return 32; // Preserve prompt decisions against a human opponent.
            const float x = entity->origin.x - observer.origin.x;
            const float y = entity->origin.y - observer.origin.y;
            const float z = entity->origin.z - observer.origin.z;
            const float distance = x * x + y * y + z * z;
            if (distance < distanceSquared)
                distanceSquared = distance;
        }
        if (target && distanceSquared < 256.0f * 256.0f)
            return 32;
        if (!target && distanceSquared < 512.0f * 512.0f)
            return 64;

        unsigned interval = target ? (population > 100 ? 96 : 64)
                                   : population > 100 ? 192 : population > 64 ? 128 : 96;
        if (s_observerCount && distanceSquared > 4096.0f * 4096.0f)
            interval *= 2;
        return interval;
    }

    bool ReuseDecision(BotDecision &previous, void *client, unsigned slot,
                       unsigned population, int32_t now)
    {
        const auto *entity = Field<Entity *>(client, 280);
        const uint16_t target = entity->sentient ? entity->sentient->targetHandle : 0;
        if (!previous.valid || previous.client != client || previous.player != entity->client ||
            previous.health != entity->health || entity->health <= 0 || previous.target != target ||
            now <= previous.command.serverTime || now < previous.thoughtTime ||
            Field<uint32_t>(client, 1368 + 8988)) // Pending script-driven buttons must run immediately.
            return false;

        // Spend decision time where humans can interact with the bots. Commands
        // still advance every server tick, including for distant cached bots.
        const unsigned interval = DecisionInterval(entity, target, population);
        const unsigned frame = SVHS_FrameDuration > 0 ? unsigned(SVHS_FrameDuration) : 16;
        const unsigned stride = (interval + frame - 1) / frame;
        if (stride <= 1 || uint32_t(now - previous.thoughtTime) >= stride * frame)
            return false;
        return (uint32_t(now) / frame + slot) % stride != 0;
    }
}

extern "C" void SV_BotUpdateBots()
{
    using namespace HostScale;
    if (!SVHS_BotSystemAllocated || !SVHS_LevelClientsAllocated)
    {
        for (auto &decision : s_decisions)
            decision.valid = false;
        return;
    }
    const uint64_t begin = Clock();
    UserCmd commands[200]{};
    const unsigned population = Enabled() ? Population() : 0;
    if (population > 20)
        GatherHumanObservers();
    else
        s_observerCount = 0;
    const int32_t now = Field<int32_t>(SVHS_ServerGlobals, 28);
    unsigned thought = 0, reused = 0;
    for (unsigned slot = 0; slot < SVHS_ClientCount && slot < 200; ++slot)
    {
        void *client = SVHS_Clients[slot];
        auto &previous = s_decisions[slot];
        auto &command = commands[slot];
        if (!SVHS_SupportsFeature(2) || Field<int32_t>(client, 214756) != 2)
        {
            previous.valid = false;
            continue;
        }
        if (SVHS_IsBotPlaying(client))
        {
            if (population > 20 && ReuseDecision(previous, client, slot, population, now))
            {
                command = previous.command;
                command.serverTime = command.commandTime = command.inputTime = now;
                ++reused;
            }
            else
            {
                // Only high-population bot decisions own an approximate-query
                // scope. Human commands, worker movement, scripts outside this
                // call, and other threads retain their native search behavior.
                const bool navigationScope = population > 20 && SV_HostNav_BeginBot();
                SVHS_BotThink(client, &command);
                if (navigationScope)
                    SV_HostNav_EndBot();
                const auto *entity = Field<Entity *>(client, 280);
                previous.command = command;
                previous.client = client;
                previous.player = entity->client;
                previous.thoughtTime = now;
                previous.health = entity->health;
                previous.target = entity->sentient ? entity->sentient->targetHandle : 0;
                previous.valid = population > 20;
                ++thought;
            }
            SVHS_AdvanceBotPriority(int(slot));
            ++SVHS_ActiveBotCount;
        }
        else
        {
            previous.valid = false;
            if (SVHS_IsBotSpectator(client))
            {
                command.serverTime = command.commandTime = command.inputTime = now;
                SVHS_BotScriptActions(static_cast<uint8_t *>(client) + 1368, &command);
                ++SVHS_ActiveBotCount;
            }
        }
        command.buttons |= 0x18002000000000ull;
    }
    auto *pings = reinterpret_cast<BotPing *>(SVHS_BotPingAnchor - offsetof(BotPing, id));
    for (unsigned i = 0; i < 32; ++i)
    {
        auto &ping = pings[i];
        if (ping.active != -1 && int32_t(uint32_t(SVHS_LevelTime) - uint32_t(ping.time)) > 3000)
        {
            SVHS_ReleaseBotPing(ping.id);
            ping.active = -1;
            ping.time = 0;
            ping.id = 0;
            ping.owner = -1;
        }
    }
    const uint64_t afterBrain = Clock();
    SV_BotApplyCommands(commands);
    RecordBotFrame(thought, reused, afterBrain - begin, Clock() - afterBrain);
}
