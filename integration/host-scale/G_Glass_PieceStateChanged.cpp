#include "sv_host_scale.h"

namespace
{
    using HostScale::Vec3;

    struct GlassPiece
    {
        uint16_t damageTaken, collapseTime;
        int32_t lastStateChangeTime;
        uint8_t impactDir, impactPos[2], opaque11;
    };

    struct GlassData
    {
        GlassPiece *pieces;
        uint32_t pieceCount;
        uint16_t damageToWeaken, damageToDestroy;
        uint32_t nameCount, opaque20;
        void *names;
        uint8_t opaque32[8];
    };

    struct GlassInitState
    {
        float quaternion[4];
        Vec3 center;
        uint8_t opaque28[24];
    };

    struct FxGlassSystem
    {
        int32_t time;
        uint32_t opaque4, pieceLimit, pieceWordCount, cellCount, activePieceCount;
        uint32_t opaque24, geoDataLimit, geoDataCount, initGeoDataCount;
        void *piecePlaces, *pieceStates, *pieceDynamics, *geoData;
        void *isInUse, *cellBits, *visData, *linkOrigin, *halfThickness, *initGeoData;
        bool needToCompactData;
        uint8_t initCount, opaque122[2];
        float effectChanceAccum;
        int32_t lastPieceDeletionTime;
        uint32_t initPieceCount;
        GlassInitState *initPieceStates;
    };

    static_assert(sizeof(GlassPiece) == 12 && offsetof(GlassPiece, impactDir) == 8);
    static_assert(sizeof(GlassData) == 40 && offsetof(GlassData, nameCount) == 16);
    static_assert(sizeof(GlassInitState) == 52 && offsetof(GlassInitState, center) == 16);
    static_assert(sizeof(FxGlassSystem) == 144 && offsetof(FxGlassSystem, initPieceStates) == 136);

    unsigned State(uint16_t damage)
    {
        if (damage == 0xffff)
            return 3;
        const auto destroy = HostScale::Field<uint16_t>(SVHS_GlassDestroyDvar, 40);
        if (damage >= destroy)
            return 2;
        return damage >= HostScale::Field<uint16_t>(SVHS_GlassWeakenDvar, 40) ? 1 : 0;
    }
} // namespace

extern "C" void G_Glass_PieceStateChanged(unsigned index,
                                          unsigned oldState,
                                          const HostScale::Vec3 *position,
                                          const HostScale::Vec3 *direction)
{
    auto *data = static_cast<GlassData *>(SVHS_GlassData);
    auto &piece = data->pieces[index];
    piece.lastStateChangeTime = SVHS_LevelTime;
    const unsigned state = State(piece.damageTaken);
    if (state == 1)
    {
        const float choice = SVHS_GlassRandom();
        if (choice >= 0.7f)
            piece.collapseTime = 0;
        else if (choice >= 0.3f)
            piece.collapseTime = uint16_t((60000 - int(SVHS_GlassRandom() * -540000.0f)) / 100);
        else
            piece.collapseTime = uint16_t((3000 - int(SVHS_GlassRandom() * -57000.0f)) / 100);
    }
    else if (state == 2)
    {
        // This is the native "destroyed without impact position" encoding.
        // Server collision may hit an unloaded FX transient on a large map;
        // authoritative damage/obstacle/script changes still apply there.
        piece.impactDir = 255;
        piece.impactPos[0] = piece.impactPos[1] = 0;
        const float length =
            direction->x * direction->x + direction->y * direction->y + direction->z * direction->z;
        if (length > 0.0f)
        {
            unsigned localIndex = 0;
            auto *system = static_cast<FxGlassSystem *>(SVHS_GlassSystem(index, &localIndex));
            if (system && system->initPieceStates && localIndex < system->initPieceCount)
            {
                Vec3 center{}, axis[3]{};
                SVHS_GlassCenter(system, localIndex, &center);
                SVHS_GlassAxis(system, localIndex, axis);
                const Vec3 delta{
                    position->x - center.x, position->y - center.y, position->z - center.z};
                piece.impactDir = SVHS_GlassDirectionByte(direction);
                piece.impactPos[0] = SVHS_GlassPackImpact(
                    (delta.y * axis[0].y + delta.x * axis[0].x) + delta.z * axis[0].z);
                piece.impactPos[1] = SVHS_GlassPackImpact(
                    (delta.y * axis[1].y + delta.x * axis[1].x) + delta.z * axis[1].z);
            }
        }
        SVHS_GlassRemoveObstacle(index);
    }
    if (oldState < 2 && state >= 2)
    {
        auto *context = SVHS_GlassScriptContext();
        SVHS_GlassAddInt(context, index);
        SVHS_GlassNotify(context, SVHS_GlassDestroyedString, 1);
    }
}
