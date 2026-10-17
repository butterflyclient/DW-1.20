#pragma once
#include <stdint.h>

// Embedded in the helper, then authenticated as part of the signed full EXE.
// Names retain the flat wire grammar for older helpers. The signed helper's
// target-derived prefix policy selects the native zone subfolder for each name.
constexpr uint32_t DW_UPDATE_ASSET_VERSION = 1;
constexpr uint32_t DW_UPDATE_ASSET_AGGREGATE_VERSION = 2;
constexpr uint32_t DW_UPDATE_ASSET_GROUPS = 2;
constexpr uint32_t DW_UPDATE_ASSET_MAX_FILES = 256;
constexpr uint64_t DW_UPDATE_ASSET_MAX_BYTES = 64ULL * 1024 * 1024;
#pragma pack(push, 1)
struct DWUpdateAssetHeader
{
    uint8_t magic[16]; // REPLAYDWASSET01 or REPLAYDWASSET02 followed by NUL.
    uint32_t version, bytes, count, reserved;
    uint8_t entriesHash[32];
    // v1: SHA256(primary FF || FP || empty FF || FP).
    // v2: SHA256(concatenated group descriptors); reserved is group count.
    uint8_t bundleHash[32];
};
struct DWUpdateAssetEntry
{
    char name[96];
    uint8_t hash[32];
    uint64_t bytes;
};
// v2 payload: descriptor followed by its entries, repeated in owner order.
// Owner 1 is bot styles; owner 2 is native weapon inspection. Each group's
// filenames bind to its own complete bundle hash. The separately embedded v1
// bot record permits older helpers to install the full EXE and catch up through
// its embedded inspection package. Map publication remains a separate protocol.
struct DWUpdateAssetGroup
{
    uint32_t owner, count;
    uint8_t bundleHash[32];
};
#pragma pack(pop)
static_assert(sizeof(DWUpdateAssetHeader) == 96);
static_assert(sizeof(DWUpdateAssetEntry) == 136);
static_assert(sizeof(DWUpdateAssetGroup) == 40);
