#pragma once
#include <stdint.h>

extern "C"
{
    bool DW_LocalProgression_LoginFields(uint64_t *user, uint64_t *xp, unsigned *appliedRank);
    void DW_LocalProgression_Frame();
    bool DW_LocalProgression_ResetRequested();
    void DW_LocalProgression_ResetAuthenticated(uint64_t user);
}
