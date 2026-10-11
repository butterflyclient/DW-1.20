#include "sv_host_scale.h"

extern "C" void CL_TransientsCollisionMP_UpdateTransientFlags(bool force)
{
    if ((SVHS_AllTilesLoadRequested != SVHS_AllTilesLoaded || force) && SVHS_AllTilesFileIndex)
        SVHS_AllTilesLoaded = SVHS_TransientFileLoaded(SVHS_AllTilesFileIndex);

    if (!SVHS_AllTilesSetupRequested || SVHS_AllTilesSetupRequested != SVHS_AllTilesSetup || force)
    {
        bool resident = false;
        if (SVHS_AllTilesSetupRequested)
        {
            resident = SVHS_CollisionTileCount != 0;
            for (unsigned tile = 0; tile < SVHS_CollisionTileCount && tile < 1024; ++tile)
            {
                const bool worldReady = SVHS_WorldTileReady(tile);
                const bool modelsReady = SVHS_StaticTileReady(tile);
                resident &= worldReady && modelsReady;
            }
        }
        else
            for (unsigned world = 0; world < 5 && !resident; ++world)
                for (unsigned word = 0; word < 32 && !resident; ++word)
                    resident = (__atomic_load_n(&SVHS_WorldTileSetup[world][word], __ATOMIC_ACQUIRE) |
                                __atomic_load_n(&SVHS_StaticTileSetup[world][word], __ATOMIC_ACQUIRE)) != 0;
        SVHS_AllTilesSetup = resident;
    }
    for (unsigned tile = 0; tile < SVHS_CollisionTileCount && tile < 1024; ++tile)
        CL_TransientsCollisionMP_UpdateTransientTileFlags(tile, force);
}
