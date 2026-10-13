#pragma once
#include "../integration/replay/dw_update_maps_protocol.h"
#include <bcrypt.h>

// Included inside update_assets, after the common IO/path/hash definitions.
struct Maps
{
    std::vector<DWUpdateMapFile> files;
    std::vector<DWUpdateMapChunk> chunks;
};

inline std::string mapPath(const DWUpdateMapFile &entry)
{
    const auto end = std::find(std::begin(entry.path), std::end(entry.path), '\0');
    require(end != std::end(entry.path) && std::all_of(end, std::end(entry.path), [](char c) { return !c; }),
            "Invalid custom map path padding");
    const std::string value(entry.path, end);
    constexpr std::string_view prefix = "mods/mw120r/maps/";
    require(value.starts_with(prefix), "Map path escaped the custom map folder");
    const auto slash = value.find('/', prefix.size());
    require(slash != std::string::npos, "Missing custom map folder");
    const auto id = value.substr(prefix.size(), slash - prefix.size());
    require(id.starts_with("mp_") && id.size() > 3 && id.size() <= 15 &&
                std::all_of(id.begin(), id.end(), [](char c)
                { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; }),
            "Invalid custom map identity");
    const auto leaf = value.substr(slash + 1);
    bool allowed = leaf == "map.json";
    for (const char *p : {"", "srv_", "eng_", "ww_", "techsets_"})
        allowed = allowed || leaf == std::string(p) + id + ".ff";
    require(allowed, "Map manifest names a non-native file");
    return value;
}

inline Maps mapManifest(const IO &io, std::span<const uint8_t> image)
{
    constexpr uint8_t magic[16] = {'R','E','P','L','A','Y','D','W','M','A','P','0','1',0,0,0};
    Maps result;
    bool found = false;
    for (size_t at = 0; at + sizeof(DWUpdateMapHeader) <= image.size(); ++at)
    {
        if (std::memcmp(image.data() + at, magic, sizeof(magic)))
            continue;
        DWUpdateMapHeader header{};
        std::memcpy(&header, image.data() + at, sizeof(header));
        if (header.version != DW_UPDATE_MAP_VERSION || !header.fileCount || !header.chunkCount ||
            header.fileCount > DW_UPDATE_MAP_MAX_FILES || header.chunkCount > DW_UPDATE_MAP_MAX_CHUNKS ||
            header.bytes != sizeof(header) + header.fileCount * sizeof(DWUpdateMapFile) +
                            header.chunkCount * sizeof(DWUpdateMapChunk) || header.bytes > image.size() - at)
            continue; // A helper's parser constants are not an embedded record.
        require(!found, "Multiple map manifests in verified executable");
        found = true;
        const auto table = image.subspan(at + sizeof(header), header.fileCount * sizeof(DWUpdateMapFile));
        require(matches(io, table, header.packageHash), "Map package identity hash failed");
        Bytes authenticated(std::begin(header.packageHash), std::end(header.packageHash));
        authenticated.insert(authenticated.end(), image.begin() + at + sizeof(header), image.begin() + at + header.bytes);
        require(matches(io, authenticated, header.entriesHash), "Map manifest table hash failed");
        result.files.resize(header.fileCount); result.chunks.resize(header.chunkCount);
        std::memcpy(result.files.data(), table.data(), table.size());
        std::memcpy(result.chunks.data(), table.data() + table.size(), result.chunks.size() * sizeof(DWUpdateMapChunk));
        uint64_t total = 0;
        uint32_t next = 0;
        std::string previous;
        std::set<std::string> names;
        std::map<std::string, unsigned> packages;
        std::map<std::wstring, std::pair<uint32_t, uint32_t>> payloads;
        for (const auto &file : result.files)
        {
            const auto value = mapPath(file);
            require((previous.empty() || previous < value) && names.insert(value).second && file.bytes && file.bytes <= DW_UPDATE_MAP_MAX_FILE_BYTES &&
                        file.firstChunk == next && file.chunkCount && file.chunkCount <= header.chunkCount - next,
                    "Duplicate, oversized or discontinuous map file");
            previous = value;
            uint64_t bytes = 0;
            for (uint32_t index = 0; index < file.chunkCount; ++index)
            {
                const auto &chunk = result.chunks[next++];
                require(chunk.bytes && chunk.bytes <= DW_UPDATE_MAP_CHUNK_BYTES && chunk.payloadBytes &&
                            chunk.payloadBytes <= DW_UPDATE_MAP_MAX_TRANSPORT_BYTES &&
                            (index + 1 == file.chunkCount || chunk.bytes == DW_UPDATE_MAP_CHUNK_BYTES),
                        "Invalid bounded map chunk");
                const auto [where, inserted] = payloads.emplace(hex(chunk.payloadHash), std::pair{chunk.bytes, chunk.payloadBytes});
                require(inserted || where->second == std::pair{chunk.bytes, chunk.payloadBytes},
                        "Inconsistent map transport payload");
                bytes += chunk.bytes;
            }
            require(bytes == file.bytes, "Map chunk coverage differs from file size");
            total += bytes;
            require(total <= DW_UPDATE_MAP_MAX_TOTAL_BYTES, "Map package exceeds total size bound");
            ++packages[value.substr(0, value.find_last_of('/'))];
        }
        require(next == header.chunkCount && total == header.uncompressedBytes,
                "Unused map chunks or inconsistent total size");
        for (const auto &[path, count] : packages)
            require(count == 6, "Custom map is missing one of its five zones or metadata");
    }
    return result;
}

inline Digest fileHash(const fs::path &path, uint64_t limit)
{
    safePath(path);
    require(fs::is_regular_file(path) && fs::file_size(path) <= limit, "Map file exceeds streaming hash bounds");
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE state{};
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
            "Map SHA256 unavailable");
    Digest result{};
    try
    {
        require(BCryptCreateHash(algorithm, &state, nullptr, 0, nullptr, 0, 0) >= 0, "Map SHA256 initialization failed");
        std::ifstream stream(path, std::ios::binary);
        require(stream.good(), "Cannot open map file for hashing");
        Bytes buffer(1024 * 1024);
        uint64_t total = 0;
        while (stream)
        {
            stream.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
            const auto count = stream.gcount();
            require(count >= 0 && uint64_t(count) <= limit - total, "Map file grew beyond hash bounds");
            total += uint64_t(count);
            if (count)
                require(BCryptHashData(state, buffer.data(), static_cast<ULONG>(count), 0) >= 0, "Map SHA256 update failed");
        }
        require(stream.eof(), "Cannot finish reading map file");
        require(BCryptFinishHash(state, result.data(), static_cast<ULONG>(result.size()), 0) >= 0,
                "Map SHA256 finish failed");
    }
    catch (...)
    {
        if (state) BCryptDestroyHash(state);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw;
    }
    BCryptDestroyHash(state); BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

inline bool fileMatches(const fs::path &path, uint64_t bytes, const uint8_t *expected, uint64_t limit)
{
    safePath(path);
    if (!fs::is_regular_file(path) || fs::file_size(path) != bytes)
        return false;
    const auto value = fileHash(path, limit);
    return std::equal(value.begin(), value.end(), expected);
}

inline void verifiedCopy(const fs::path &source, const fs::path &target, uint64_t bytes,
                         const uint8_t *expected, uint64_t limit)
{
    safePath(source); safePath(target);
    require(fileMatches(source, bytes, expected, limit), "Asset changed before streaming copy");
    require(CopyFileW(source.c_str(), target.c_str(), FALSE) != 0, "Cannot copy staged asset or recovery file");
    require(fileMatches(target, bytes, expected, limit), "Streaming asset copy failed verification");
}
