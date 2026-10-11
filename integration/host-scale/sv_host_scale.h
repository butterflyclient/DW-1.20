#pragma once
#include <stddef.h>
#include <stdint.h>
#include "SV_HostScaleBindings.h"

// Views cover every byte consumed by the native replacements. Unidentified
// fields stay opaque; they are never initialized or replaced by this module.
namespace HostScale
{
    struct UserCmd
    {
        uint64_t buttons;
        uint32_t opaque8;
        int32_t serverTime, commandTime, inputTime;
        uint8_t remaining[240];
    };
    struct ThinkQueue
    {
        UserCmd commands[6];
        uint32_t writeIndex, readIndex;
        int32_t pending;
        uint32_t reserved;
    };
    struct Vec3 { float x, y, z; };
    struct Sentient;
    struct Entity
    {
        int16_t number;
        uint8_t opaque2[6];
        uint16_t type;
        uint8_t opaque10[294];
        Vec3 origin;
        uint8_t opaque316[20];
        uint8_t *client;
        Sentient *sentient;
        uint8_t opaque352[64];
        uint32_t flags;
        uint8_t opaque420[20];
        int32_t health;
        uint8_t opaque444[996];
    };
    struct Sentient
    {
        Entity *entity;
        uint8_t opaque8[8];
        uint32_t team;
        uint8_t opaque20[52];
        uint16_t targetHandle;
        uint8_t opaque74[82];
        bool neutralSenses;
        uint8_t opaque157[27];
    };
    struct SentientInfo
    {
        uint8_t visible, peripheral, obscured, opaque3;
        int32_t lastUpdateTime;
        uint8_t opaque8[56];
    };
    struct AICommon
    {
        Entity *entity;
        Sentient *sentient;
        SentientInfo *info;
        uint8_t opaque24[64];
        float highlyAwareRadius;
        uint8_t opaque92[72];
        float maximumSightDistanceSquared;
        uint8_t opaque168[8];
        int32_t sightLatency;
        uint8_t opaque180[264];
        uint32_t traceCount;
    };
    struct AIInterface
    {
        const uintptr_t *vtable;
        AICommon *ai;
    };
    struct TeamFlags { uint32_t words[5]; };
    struct SightCandidate { Sentient *sentient; float priority, distanceSquared; };
    struct BotPing
    {
        int32_t owner, time;
        uint32_t id;
        int32_t active;
    };
    static_assert(sizeof(UserCmd) == 264 && offsetof(UserCmd, serverTime) == 12);
    static_assert(sizeof(ThinkQueue) == 1600 && offsetof(ThinkQueue, pending) == 1592);
    static_assert(sizeof(Entity) == 1440 && offsetof(Entity, client) == 336);
    static_assert(offsetof(Entity, origin) == 304 && offsetof(Entity, health) == 440);
    static_assert(sizeof(Sentient) == 184 && offsetof(Sentient, targetHandle) == 72);
    static_assert(offsetof(Sentient, neutralSenses) == 156 && sizeof(SentientInfo) == 64);
    static_assert(offsetof(AICommon, highlyAwareRadius) == 88);
    static_assert(offsetof(AICommon, maximumSightDistanceSquared) == 164);
    static_assert(offsetof(AICommon, sightLatency) == 176 && offsetof(AICommon, traceCount) == 444);
    static_assert(sizeof(TeamFlags) == 20 && sizeof(SightCandidate) == 16);
    static_assert(sizeof(BotPing) == 16 && offsetof(BotPing, id) == 8);
    static_assert(sizeof(SVHS_WorldTileSetup) == 5 * 32 * sizeof(uint32_t));
    static_assert(sizeof(SVHS_StaticTileSetup) == sizeof(SVHS_WorldTileSetup));

    template<class T> T &Field(void *address, size_t offset)
    {
        return *reinterpret_cast<T *>(static_cast<uint8_t *>(address) + offset);
    }

    bool Enabled();
    unsigned Population();
    void RecordSight(unsigned candidates, unsigned evaluations, unsigned deferred);
    void RecordMovement(unsigned queued, unsigned serial);
    void RecordBackpressure();
    uint64_t Clock();
    void RecordBotFrame(unsigned thought, unsigned reused, uint64_t brain, uint64_t movement);

    inline bool CollisionTileResident(unsigned tile)
    {
        const unsigned word = tile >> 5;
        const uint32_t mask = 0x80000000u >> (tile & 31);
        // Read the per-world release acknowledgements, not the all-world-ready
        // predicate. A slow server must retain its shapes after client release.
        for (unsigned world = 0; world != 5; ++world)
            if ((__atomic_load_n(&SVHS_WorldTileSetup[world][word], __ATOMIC_ACQUIRE) |
                 __atomic_load_n(&SVHS_StaticTileSetup[world][word], __ATOMIC_ACQUIRE)) & mask)
                return true;
        return false;
    }
}

extern "C"
{
    void SV_HostScale_Frame();
    void AICommon_UpdateSight(HostScale::AIInterface *);
    void SV_BotApplyCommands(HostScale::UserCmd *);
    void SV_BotUpdateBots();
    bool SV_UserMoveWorkersMP_TryQueueClientThinkCmd(unsigned, const HostScale::UserCmd *);
    void CL_TransientsCollisionMP_UpdateTransientTileFlags(unsigned, bool);
    void CL_TransientsCollisionMP_UpdateTransientFlags(bool);
}
