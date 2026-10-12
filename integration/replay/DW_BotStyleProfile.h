#pragma once
#include <stdint.h>

extern "C" bool DW_BotPolicy_ProfileSeed(unsigned client, uint64_t *seed);

extern "C" bool DW_BotRank_Apply(unsigned client);
