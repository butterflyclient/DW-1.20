#include <windows.h>
#include <bcrypt.h>
#include <compressapi.h>
#include <filesystem>
#include <vector>
#include <fstream>
#include <string>
#include <stdexcept>
#include <span>
#include <array>
#include <cstring>
#include <algorithm>
#include <iostream>
#include "replay-update-assets.h"

namespace
{
    using namespace update_assets;
    fs::path payloadFolder;
    unsigned writes, failWrite, downloads;
    bool corruptDownload;
    Bytes read(const fs::path &path, uint64_t limit)
    {
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        require(stream.good(), "Fixture input unavailable");
        const auto size = stream.tellg();
        require(size >= 0 && uint64_t(size) <= limit, "Fixture input bound");
        Bytes data(static_cast<size_t>(size)); stream.seekg(0);
        stream.read(reinterpret_cast<char *>(data.data()), data.size());
        require(stream.good(), "Fixture read failed"); return data;
    }
    void write(const fs::path &path, std::span<const uint8_t> bytes)
    {
        if (failWrite && ++writes == failWrite)
            throw std::runtime_error("Injected fixture write failure");
        const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        require(handle != INVALID_HANDLE_VALUE, "Fixture write open failed");
        DWORD count = 0;
        const bool ok = WriteFile(handle, bytes.data(), DWORD(bytes.size()), &count, nullptr) &&
                        count == bytes.size() && FlushFileBuffers(handle);
        CloseHandle(handle); require(ok, "Fixture write failed");
    }
    Digest hash(std::span<const uint8_t> bytes)
    {
        BCRYPT_ALG_HANDLE algorithm{}; BCRYPT_HASH_HANDLE digest{}; Digest result{};
        require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
                "Fixture SHA256 open failed");
        const bool ok = BCryptCreateHash(algorithm, &digest, nullptr, 0, nullptr, 0, 0) >= 0 &&
                        BCryptHashData(digest, const_cast<PUCHAR>(bytes.data()), ULONG(bytes.size()), 0) >= 0 &&
                        BCryptFinishHash(digest, result.data(), ULONG(result.size()), 0) >= 0;
        if (digest) BCryptDestroyHash(digest); BCryptCloseAlgorithmProvider(algorithm, 0);
        require(ok, "Fixture SHA256 failed"); return result;
    }
    Bytes download(const std::wstring &, const std::wstring &url, std::span<const uint8_t> body, uint64_t size)
    {
        const std::wstring prefix = L"/updates/v2/asset/";
        require(url.starts_with(prefix) && body.empty(), "Fixture immutable route failed");
        ++downloads;
        auto bytes = read(payloadFolder / (url.substr(prefix.size()) + L".bin"), DW_UPDATE_ASSET_MAX_BYTES);
        require(bytes.size() == size, "Fixture immutable size failed");
        if (corruptDownload) bytes[0] ^= 1;
        return bytes;
    }
    unsigned decompressions = 0;
    Bytes decompress(std::span<const uint8_t> compressed, uint32_t size)
    {
        ++decompressions;
        require(size <= DW_UPDATE_MAP_CHUNK_BYTES && compressed.size() <= DW_UPDATE_MAP_MAX_TRANSPORT_BYTES,
                "Fixture decompressor bound");
        DECOMPRESSOR_HANDLE decoder{};
        require(CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &decoder) != 0, "Fixture decoder creation");
        Bytes output(size); SIZE_T actual = 0;
        const bool ok = Decompress(decoder, const_cast<uint8_t *>(compressed.data()), compressed.size(),
                                   output.data(), output.size(), &actual) != 0;
        CloseDecompressor(decoder);
        require(ok && actual == size, "Fixture decoder output");
        return output;
    }
    IO backend{read, write, hash, download, decompress};
}

int wmain(int argc, wchar_t **argv)
{
    try
    {
        require(argc == 4, "Map fixture arguments");
        const auto image = read(argv[2], 1024 * 1024);
        const auto maps = mapManifest(backend, image);
        if (std::wstring(argv[1]) == L"--parse")
        {
            require(!maps.files.empty(), "Map fixture missing manifest");
            std::cout << "PASS map parser\n"; return 0;
        }
        require(maps.files.size() == 6, "Map fixture six-file contract");
        const fs::path root = fs::absolute(argv[1]); payloadFolder = argv[3];
        const auto entries = manifest(backend, image); const auto identity = hash(image);
        require(!entries.empty(), "Mixed fixture legacy manifest missing");
        const auto original = Bytes{'o','r','i','g','i','n','a','l'}, shipped = Bytes{'s','t','o','c','k'};
        unsigned cases = 0;
        for (unsigned test = 0; test < 6; ++test)
        {
            const auto game = root / std::to_wstring(test);
            fs::create_directories(game / "zone");
            write(game / "game.exe", image); write(game / "zone/common_base_mp.ff", shipped);
            for (const auto &entry : entries)
            {
                const auto path = game / "zone" / nativeRelativePath(entry);
                fs::create_directories(path.parent_path());
                // Corruption test reaches map transport without downloading overlays.
                write(path, test == 1 ? read(payloadFolder / (hex(entry.hash) + L".bin"), DW_UPDATE_ASSET_MAX_BYTES) : original);
            }
            if (test != 3)
                for (const auto &entry : maps.files)
                {
                    const auto path = game / mapPath(entry);
                    fs::create_directories(path.parent_path()); write(path, original);
                }
            Session session(backend, game / "game.exe", game / "game.exe.update", image, identity.data());
            downloads = decompressions = 0; corruptDownload = test == 1;
            bool failed = false;
            try { session.stage(L"fixture"); } catch (const std::exception &) { failed = true; }
            corruptDownload = false;
            require(failed == (test == 1), "Map fixture corruption disposition");
            if (failed)
            {
                require(decompressions == 0, "Unauthenticated transport reached Cabinet");
                for (const auto &entry : maps.files) require(read(game / mapPath(entry), 100) == original, "Failed staging changed map");
                ++cases; continue;
            }
            require(decompressions >= 5 && decompressions <= maps.chunks.size(), "Map fixture chunk decoding/reuse");
            if (test == 2)
            {
                const auto changed = game / "game.exe.update/asset-staging" / hex(identity.data()) /
                                     (L"map-" + hex(maps.files[0].hash) + L".bin");
                write(changed, original);
            }
            HANDLE locked = INVALID_HANDLE_VALUE;
            if (test == 4)
                locked = CreateFileW((game / mapPath(maps.files[2])).c_str(), GENERIC_READ, FILE_SHARE_READ,
                                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            try { session.install(); } catch (const std::exception &) { failed = true; }
            if (locked != INVALID_HANDLE_VALUE) CloseHandle(locked);
            require(failed == (test == 2 || test == 4), "Map fixture changed staging / atomic failure handling");
            if (failed)
            {
                for (const auto &entry : entries) require(read(game / "zone" / nativeRelativePath(entry), 100) == original, "Mixed rollback lost overlay");
                for (const auto &entry : maps.files) require(read(game / mapPath(entry), 100) == original, "Mixed rollback lost map");
            }
            else
            {
                require(!session.needed(), "Map fixture installed hashes differ");
                if (test == 5)
                {
                    session.commit();
                    require(!session.needed(), "Map fixture commit lost files");
                }
                else
                {
                    session.rollback();
                    for (const auto &entry : entries) require(read(game / "zone" / nativeRelativePath(entry), 100) == original, "Explicit mixed rollback lost overlay");
                    for (const auto &entry : maps.files)
                        require(test == 3 ? !fs::exists(game / mapPath(entry)) : read(game / mapPath(entry), 100) == original,
                                "Explicit mixed rollback lost map");
                }
            }
            require(read(game / "zone/common_base_mp.ff", 100) == shipped, "Shipped asset was changed");
            ++cases;
        }
        std::cout << "PASS " << cases << " bounded-map and mixed Windows transaction cases\n";
        return 0;
    }
    catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
