#pragma once
#include <stdint.h>

// Optional record authenticated by the signed full executable. Keep ASSET01
// unchanged so older helpers can replace the EXE before discovering maps.
constexpr uint32_t DW_UPDATE_MAP_VERSION = 1;
constexpr uint32_t DW_UPDATE_MAP_XPRESS_HUFF = 1;
constexpr uint32_t DW_UPDATE_MAP_MAX_FILES = 256;
constexpr uint32_t DW_UPDATE_MAP_MAX_CHUNKS = 4096;
constexpr uint32_t DW_UPDATE_MAP_CHUNK_BYTES = 4 * 1024 * 1024;
constexpr uint32_t DW_UPDATE_MAP_MAX_TRANSPORT_BYTES = 8 * 1024 * 1024;
constexpr uint64_t DW_UPDATE_MAP_MAX_FILE_BYTES = 2ULL * 1024 * 1024 * 1024;
constexpr uint64_t DW_UPDATE_MAP_MAX_TOTAL_BYTES = 4ULL * 1024 * 1024 * 1024;

#pragma pack(push, 1)
struct DWUpdateMapHeader
{
    uint8_t magic[16]; // REPLAYDWMAP01 followed by three NUL bytes.
    uint32_t version, bytes, fileCount, chunkCount;
    uint64_t uncompressedBytes;
    uint8_t entriesHash[32]; // SHA256(packageHash || file table || chunk table).
    uint8_t packageHash[32]; // SHA256(file table), independent of compression.
};
struct DWUpdateMapFile
{
    char path[128]; // mods/mw120r/maps/<map id>/<native file>, relative to game.
    uint8_t hash[32];
    uint64_t bytes;
    uint32_t firstChunk, chunkCount;
};
struct DWUpdateMapChunk
{
    uint8_t hash[32]; // Exact decompressed chunk.
    uint8_t payloadHash[32]; // Exact compressed transport chunk.
    uint32_t bytes, payloadBytes;
};
#pragma pack(pop)
static_assert(sizeof(DWUpdateMapHeader) == 104);
static_assert(sizeof(DWUpdateMapFile) == 176);
static_assert(sizeof(DWUpdateMapChunk) == 72);
