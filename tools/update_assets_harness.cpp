#include <windows.h>
#include <bcrypt.h>
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
    IO backend{read, write, hash, download};
}

int wmain(int argc, wchar_t **argv)
{
    try
    {
        require(argc == 4, "Fixture arguments");
        const fs::path root = fs::absolute(argv[1]), imagePath = argv[2];
        payloadFolder = argv[3];
        const auto image = read(imagePath, 1024 * 1024);
        const auto identity = hash(image);
        const auto entries = manifest(backend, image);
        require(entries.size() == 60, "Fixture complete native locale list");
        for (const auto &entry : entries)
        {
            auto future = entry;
            const auto value = name(entry);
            const auto at = value.find("dw_bot_styles_mp_") + 17;
            std::fill(future.name + at, future.name + at + 16, 'a');
            require(nativeRelativePath(future).parent_path() == nativeRelativePath(entry).parent_path(),
                    "Future bundle changed native folder mapping");
            if (value.starts_with("ww_"))
                require(nativeRelativePath(entry).parent_path() == "worldwide", "Native regional path mismatch");
            if (value.starts_with("eng_"))
                require(nativeRelativePath(entry).parent_path() == "english", "Native language path mismatch");
        }
        const auto original = Bytes{'o','r','i','g','i','n','a','l'};
        const auto shipped = Bytes{'s','h','i','p','p','e','d'};
        unsigned cases = 0;
        for (unsigned test = 0; test < 5; ++test)
        {
            const auto game = root / std::to_wstring(test);
            fs::create_directories(game / "zone");
            write(game / "game.exe", image); write(game / "zone/common_base_mp.ff", shipped);
            if (test != 3)
                for (const auto &entry : entries)
                {
                    const auto destination = game / "zone" / nativeRelativePath(entry);
                    fs::create_directories(destination.parent_path());
                    write(destination, original);
                }
            Session session(backend, game / "game.exe", game / "game.exe.update", image, identity.data());
            require(session.needed(), "Fixture missing assets not detected");
            downloads = 0; corruptDownload = test == 1;
            bool failed = false;
            try { session.stage(L"fixture"); } catch (const std::exception &) { failed = true; }
            require(failed == (test == 1), "Fixture corrupted download accepted");
            corruptDownload = false;
            if (failed)
            {
                for (const auto &entry : entries) require(read(game / "zone" / nativeRelativePath(entry), MAXDWORD) == original, "Failed download changed installed assets");
                ++cases; continue;
            }
            require(downloads == 4, "Fixture did not reuse four content-addressed payloads");
            if (test == 2)
            {
                const auto first = game / "game.exe.update/asset-staging" / hex(identity.data()) / (hex(entries[0].hash) + L".bin");
                write(first, original);
                try { session.install(); } catch (const std::exception &error)
                { failed = true; std::cerr << "test" << test << ": " << error.what() << " Windows=" << GetLastError() << '\n'; }
                require(failed, "Fixture changed staging accepted");
            }
            else
            {
                writes = 0; failWrite = test == 4 ? 6 : 0;
                try { session.install(); } catch (const std::exception &error)
                { failed = true; std::cerr << "test" << test << ": " << error.what() << " Windows=" << GetLastError() << '\n'; }
                failWrite = 0;
                require(failed == (test == 4), "Fixture replacement failure handling");
            }
            if (failed)
            {
                for (const auto &entry : entries) require(read(game / "zone" / nativeRelativePath(entry), MAXDWORD) == original, "Fixture rollback lost original assets");
            }
            else
            {
                require(!session.needed(), "Fixture installed assets invalid");
                if (test == 0)
                {
                    const auto backups = game / "game.exe.update/asset-backups" / hex(identity.data());
                    require(std::distance(fs::directory_iterator(backups), fs::directory_iterator{}) == 61, "Fixture original backups or recovery journal missing");
                    session.rollback();
                    for (const auto &entry : entries) require(read(game / "zone" / nativeRelativePath(entry), MAXDWORD) == original, "Explicit rollback failed");
                }
                else
                {
                    session.rollback();
                    for (const auto &entry : entries) require(!fs::exists(game / "zone" / nativeRelativePath(entry)), "New-asset rollback failed");
                }
            }
            require(read(game / "zone/common_base_mp.ff", MAXDWORD) == shipped, "Shipped original changed");
            ++cases;
        }
        std::cout << "PASS " << cases << " real Windows owned-asset backup/replace/rollback cases\n";
        return 0;
    }
    catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
