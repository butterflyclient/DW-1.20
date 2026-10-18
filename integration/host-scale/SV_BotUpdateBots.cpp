#include "sv_host_navigation.h"
#include "sv_host_bot_equipment.h"
#include "DW_BotStyleProfile.h"

extern "C" bool DW_BotPolicy_IsBattleRoyale();
extern "C" void SV_HostBot_UpdateTravelUrgency(void *, HostScale::UserCmd *, bool);
#include "sv_host_bot_loot.h"
#include "SV_HostBotGpuPlanner.h"
#include <string.h>

namespace
{
    using namespace HostScale;

    struct EquipmentStamp
    {
        uint32_t inventory[15], currentWeapon, phase, scriptFlags;
        int32_t movementType;
        BotWeapon scriptWeapon;
    };

    EquipmentStamp Equipment(const Entity *entity, const void *client)
    {
        const auto *player = reinterpret_cast<const BotEquipmentPlayer *>(entity->client);
        const auto *bot =
            reinterpret_cast<const BotEquipmentData *>(static_cast<const uint8_t *>(client) + 1368);
        EquipmentStamp stamp{};
        memcpy(stamp.inventory, player->inventory, sizeof(stamp.inventory));
        stamp.currentWeapon = player->currentWeapon;
        stamp.phase = player->gameExtraInfo & 0x600;
        stamp.scriptFlags = bot->scriptFlags;
        stamp.movementType = player->movementType;
        stamp.scriptWeapon = bot->scriptWeapon;
        return stamp;
    }

    struct BotDecision
    {
        UserCmd command;
        void *client, *player;
        const Entity *entity;
        int32_t thoughtTime;
        int32_t health;
        uint16_t target;
        bool valid;
        Vec3 origin;
        EquipmentStamp equipment;
        const void *mapStatics;
        uint64_t jailProfile;
        uint32_t jailWeaponFlags;
        bool jailMapped;
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
        uint64_t profile = 0;
        const bool responsive = DW_BotPolicy_ProfileSeed(uint16_t(entity->number), &profile);
        const unsigned frame = SVHS_FrameDuration > 0 ? unsigned(SVHS_FrameDuration) : 16;
        // Close bot-vs-bot combat needs the same prompt melee, aim and weapon
        // decisions as combat against a human. Distance to spectators alone
        // must not determine the responsiveness of an acquired opponent.
        if (target && target <= SVHS_ClientCount && target <= 200)
        {
            const void *client = SVHS_Clients[target - 1];
            const Entity *enemy =
                client ? Field<Entity *>(const_cast<void *>(client), 280) : nullptr;
            if (enemy && enemy->health > 0)
            {
                if (responsive)
                    return frame; // Aim/fire decisions advance with every movement tick.
                const float x = enemy->origin.x - entity->origin.x;
                const float y = enemy->origin.y - entity->origin.y;
                const float z = enemy->origin.z - entity->origin.z;
                const float distance = x * x + y * y + z * z;
                if (distance < 768.0f * 768.0f)
                    return 32;
                if (distance < 2048.0f * 2048.0f)
                    return 64;
            }
        }
        float distanceSquared = 3.402823466e38f;
        for (unsigned i = 0; i < s_observerCount; ++i)
        {
            const auto &observer = s_observers[i];
            if (target && target == observer.targetHandle)
                return responsive ? frame : 32;
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
            return responsive ? frame : 64;
        if (responsive && !target && distanceSquared < 2048.0f * 2048.0f)
            return frame; // Detect a nearby human promptly, with native sight/aim checks.

        unsigned interval = target             ? (population > 100 ? 96 : 64)
                            : population > 100 ? 192
                            : population > 64  ? 128
                                               : 96;
        if (s_observerCount && distanceSquared > 4096.0f * 4096.0f)
            interval *= 2;
        return interval;
    }

    bool ReuseDecision(
        BotDecision &previous, void *client, unsigned slot, unsigned population, int32_t now, bool battleRoyale)
    {
        const auto *entity = Field<Entity *>(client, 280);
        const uint16_t target = entity->sentient ? entity->sentient->targetHandle : 0;
        const float x = entity->origin.x - previous.origin.x;
        const float y = entity->origin.y - previous.origin.y;
        const float z = entity->origin.z - previous.origin.z;
        if (!previous.valid || previous.client != client || previous.player != entity->client || previous.entity != entity ||
            previous.mapStatics != SVHS_GameStatics || previous.health != entity->health ||
            entity->health <= 0 || previous.target != target ||
            now <= previous.command.serverTime || now < previous.thoughtTime ||
            Field<uint32_t>(client,
                            1368 + 8988)) // Pending script-driven buttons must run immediately.
            return false;
        // A script teleport can follow an earlier phase change. Compare against
        // the last full think, not the last replayed movement command.
        if (x * x + y * y + z * z > 256.0f * 256.0f)
            return false;
        const auto *bot = reinterpret_cast<const BotEquipmentData *>(
            static_cast<const uint8_t *>(client) + 1368);
        const auto *player = reinterpret_cast<const BotEquipmentPlayer *>(entity->client);
        const uint32_t phase = player->gameExtraInfo & 0x600;
        const bool waitingJail = phase == 0x200;
        if (phase && !waitingJail)
            return false; // Arena and overlapping transition bits always think now.
        if (waitingJail)
        {
            // Stock bot_gulag_think clears enemies and script goals while the
            // jail waits. Only replay an idle native decision, never an action
            // or a walking command. A decision containing any native button
            // keeps its full native cadence, preserving stock action/flag bits.
            uint64_t profile = 0;
            if (!battleRoyale || x != 0.0f || y != 0.0f || z != 0.0f ||
                target || Field<uint32_t>(client, 1368 + 516) ||
                (bot->grenadeFlags & 3) || bot->grenadeHoldUntil > now ||
                previous.command.buttons ||
                Field<uint16_t>(&previous.command, 156) || !previous.jailMapped ||
                player->weaponFlags != previous.jailWeaponFlags ||
                !DW_BotPolicy_ProfileSeed(slot, &profile) || profile != previous.jailProfile)
                return false;
        }
        if (target && target <= SVHS_ClientCount && target <= 200)
        {
            void *other = SVHS_Clients[target - 1];
            const Entity *enemy = other ? Field<Entity *>(other, 280) : nullptr;
            if (!enemy || enemy->health <= 0)
                return false; // Never reuse a hold/fire decision after its target died.
        }
        const EquipmentStamp current = Equipment(entity, client);
        if (memcmp(&previous.equipment, &current, sizeof(current)) != 0)
            return false;

        // Spend decision time where humans can interact with the bots. Commands
        // still advance every server tick, including for distant cached bots.
        const unsigned frame = SVHS_FrameDuration > 0 ? unsigned(SVHS_FrameDuration) : 16;
        const unsigned interval = waitingJail ? 64 : DecisionInterval(entity, target, population);
        // Round the jail interval down: a 20 ms server runs native thoughts at
        // least every 60 ms, rather than rounding a 64 ms bound up to 80 ms.
        const unsigned stride = waitingJail ? interval / frame : (interval + frame - 1) / frame;
        if (stride <= 1 || uint32_t(now - previous.thoughtTime) >= stride * frame)
            return false;
        return (uint32_t(now) / frame + slot) % stride != 0;
    }
} // namespace

extern "C" void SV_BotUpdateBots()
{
    using namespace HostScale;
    HostBotPlanner::BeginServerFrame(SVHS_BotSystemAllocated && SVHS_LevelClientsAllocated);
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
    const bool battleRoyale = population > 20 && DW_BotPolicy_IsBattleRoyale();
    unsigned thought = 0, reused = 0;
    for (unsigned slot = 0; slot < SVHS_ClientCount && slot < 200; ++slot)
    {
        void *client = SVHS_Clients[slot];
        auto &previous = s_decisions[slot];
        auto &command = commands[slot];
        if (!SVHS_SupportsFeature(2) || Field<int32_t>(client, 214756) != 2)
        {
            previous.valid = false;
            HostBotPlanner::Cancel(slot);
            continue;
        }
        if (SVHS_IsBotPlaying(client))
        {
            void *data = static_cast<uint8_t *>(client) + 1368;
            bool reusedCommand = false;
            bool reusedJail = false;
            if (SV_HostBot_PrepareEquipment(data))
                previous.valid = false;
            if (population > 20 && ReuseDecision(previous, client, slot, population, now, battleRoyale))
            {
                command = previous.command;
                command.serverTime = command.commandTime = command.inputTime = now;
                reusedJail = (previous.equipment.phase == 0x200);
                if (!reusedJail)
                {
                    SV_HostNav_RefreshBotMovement(data, &command);
                    SV_HostBot_FaceLoot(data, &command);
                }
                ++reused;
                reusedCommand = true;
            }
            else
            {
                // Only high-population bot decisions own an approximate-query
                // scope. Human commands, worker movement, scripts outside this
                // call, and other threads retain their native search behavior.
                // Gulag entry needs exact current-area resolution on every
                // native think while its teleport and arena route settle.
                const bool navigationScope =
                    population > 20 && !SV_HostBot_InGulag(data) && SV_HostNav_BeginBot();
                SVHS_BotThink(client, &command);
                if (navigationScope)
                    SV_HostNav_EndBot();
                SV_HostBot_UpdateLoot(data, &command);
                SV_HostBot_FaceLoot(data, &command);
                const auto *entity = Field<Entity *>(client, 280);
                previous.command = command;
                previous.client = client;
                previous.player = entity->client;
                previous.entity = entity;
                previous.thoughtTime = now;
                previous.health = entity->health;
                previous.origin = entity->origin;
                previous.target = entity->sentient ? entity->sentient->targetHandle : 0;
                previous.equipment = Equipment(entity, client);
                previous.mapStatics = SVHS_GameStatics;
                previous.jailMapped = previous.equipment.phase == 0x200 && battleRoyale &&
                    DW_BotPolicy_ProfileSeed(slot, &previous.jailProfile);
                previous.jailWeaponFlags = reinterpret_cast<const BotEquipmentPlayer *>(
                    entity->client)->weaponFlags;
                previous.valid = population > 20;
                ++thought;
            }
            // Travel intent belongs to every playing bot, including normal
            // population full thoughts. The cached base command remains native
            // so added sprint requests cannot become stale decision buttons.
            if (!reusedCommand && SV_HostBot_GasEvacuationRequired(data))
                SV_HostNav_RefreshBotMovement(data, &command);
            if (!reusedJail)
                SV_HostBot_UpdateTravelUrgency(data, &command, reusedCommand);
            SVHS_AdvanceBotPriority(int(slot));
            ++SVHS_ActiveBotCount;
        }
        else
        {
            previous.valid = false;
            HostBotPlanner::Cancel(slot);
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
    HostBotPlanner::EndServerFrame();
    SV_BotApplyCommands(commands);
    RecordBotFrame(thought, reused, afterBrain - begin, Clock() - afterBrain);
}
