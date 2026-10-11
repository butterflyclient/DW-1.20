#include "sv_host_scale.h"

extern "C" void CL_TransientsCollisionMP_UpdateTransientTileFlags(unsigned tile, bool force)
{
    if (tile >= 1024)
        return;
    const unsigned word = tile >> 5;
    const uint32_t mask = 0x80000000u >> (tile & 31);
    const bool loadRequested = (SVHS_TileLoadRequested[word] & mask) != 0;
    if ((loadRequested != bool(SVHS_TileLoaded[word] & mask) || force) && SVHS_TileFileIndices[tile])
    {
        if (SVHS_TransientFileLoaded(SVHS_TileFileIndices[tile]))
            SVHS_TileLoaded[word] |= mask;
        else
            SVHS_TileLoaded[word] &= ~mask;
    }

    const bool setupRequested = (SVHS_TileSetupRequested[word] & mask) != 0;
    if (!setupRequested || setupRequested != bool(SVHS_TileSetup[word] & mask) || force)
    {
        bool resident;
        if (setupRequested)
        {
            const bool worldReady = SVHS_WorldTileReady(tile);
            const bool modelsReady = SVHS_StaticTileReady(tile);
            resident = worldReady && modelsReady;
        }
        else
            resident = HostScale::CollisionTileResident(tile);
        // Correctness fix in every optimization profile: the DB unload gate
        // must stay closed while ANY world still owns either kind of body.
        if (resident)
            SVHS_TileSetup[word] |= mask;
        else
            SVHS_TileSetup[word] &= ~mask;
    }
}
