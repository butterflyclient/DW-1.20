#pragma once
#include <stdint.h>

// Embedded in the helper, then authenticated as part of the signed full EXE.
// Names retain the flat wire grammar for older helpers. The signed helper's
// target-derived prefix policy selects the native zone subfolder for each name.
constexpr uint32_t DW_UPDATE_ASSET_VERSION = 1;
constexpr uint32_t DW_UPDATE_ASSET_MAX_FILES = 256;
constexpr uint64_t DW_UPDATE_ASSET_MAX_BYTES = 64ULL * 1024 * 1024;
#pragma pack(push, 1)
struct DWUpdateAssetHeader
{
    uint8_t magic[16]; // REPLAYDWASSET01 followed by NUL.
    uint32_t version, bytes, count, reserved;
    uint8_t entriesHash[32];
    uint8_t bundleHash[32]; // SHA256(primary FF || FP || empty FF || FP).
};
struct DWUpdateAssetEntry
{
    char name[96];
    uint8_t hash[32];
    uint64_t bytes;
};
#pragma pack(pop)
static_assert(sizeof(DWUpdateAssetHeader) == 96);
static_assert(sizeof(DWUpdateAssetEntry) == 136);
