// Standalone identity/DPAPI checks do not run the game's progression sampler.
// Production builds link DW_LocalProgression.cpp and DW_LocalConfig.cpp instead.
#include <cstdint>

extern "C" bool DW_LocalProgression_LoginFields(
    uint64_t *user, uint64_t *xp, unsigned *appliedRank)
{
    *user = *xp = 0;
    *appliedRank = 0;
    return false;
}

extern "C" unsigned DW_LocalConfig_Rank()
{
    return 0;
}

extern "C" bool DW_LocalProgression_ResetRequested()
{
    return false;
}
