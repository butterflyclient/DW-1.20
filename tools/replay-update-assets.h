#pragma once
#include "../integration/replay/dw_update_assets_protocol.h"
#include "DW_UpdateAssetPaths.h"
#include <string_view>
#include <optional>
#include <set>
#include <map>

namespace update_assets
{
    namespace fs = std::filesystem;
    using Bytes = std::vector<uint8_t>;
    using Digest = std::array<uint8_t, 32>;
    struct IO
    {
        Bytes (*read)(const fs::path &, uint64_t);
        void (*write)(const fs::path &, std::span<const uint8_t>);
        Digest (*hash)(std::span<const uint8_t>);
        Bytes (*download)(const std::wstring &, const std::wstring &, std::span<const uint8_t>, uint64_t);
    };
    inline void require(bool condition, const char *message)
    {
        if (!condition)
            throw std::runtime_error(message);
    }
    inline std::wstring hex(const uint8_t *bytes)
    {
        std::wstring result;
        for (unsigned i = 0; i < 32; ++i)
        {
            result += L"0123456789abcdef"[bytes[i] >> 4];
            result += L"0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }
    inline std::string asciiHex(const uint8_t *bytes)
    {
        std::string result;
        for (unsigned i = 0; i < 32; ++i)
        {
            result += "0123456789abcdef"[bytes[i] >> 4];
            result += "0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }
    inline bool matches(const IO &io, std::span<const uint8_t> bytes, const uint8_t *expected)
    {
        const auto digest = io.hash(bytes);
        return std::equal(digest.begin(), digest.end(), expected);
    }
    inline void safePath(const fs::path &path)
    {
        const auto flags = GetFileAttributesW(path.c_str());
        if (flags != INVALID_FILE_ATTRIBUTES)
            require(!(flags & FILE_ATTRIBUTE_REPARSE_POINT), "Asset update path is a reparse point");
        else
            require(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND,
                    "Asset update path cannot be inspected");
    }
    inline void directory(const fs::path &path)
    {
        safePath(path);
        if (!fs::exists(path))
            fs::create_directory(path);
        require(fs::is_directory(path), "Asset update directory is unavailable");
        safePath(path);
    }
    inline std::string name(const DWUpdateAssetEntry &entry)
    {
        const auto end = std::find(std::begin(entry.name), std::end(entry.name), '\0');
        require(end != std::end(entry.name) && std::all_of(end, std::end(entry.name), [](char c) { return c == 0; }),
                "Invalid owned asset name padding");
        std::string value(entry.name, end);
        constexpr char owner[] = "dw_bot_styles_mp_";
        const auto at = value.find(owner);
        require(at != std::string::npos && at <= 17 &&
                    (at == 0 || value[at - 1] == '_') &&
                    std::all_of(value.begin(), value.begin() + at, [](char c)
                    { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; }) &&
                    value.size() == at + sizeof(owner) - 1 + 16 + 3 &&
                    (value.ends_with(".ff") || value.ends_with(".fp")),
                "Asset manifest attempts to replace a shipped or non-zone file");
        const auto begin = value.begin() + at + sizeof(owner) - 1;
        require(std::all_of(begin, begin + 16, [](char c)
                { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }),
                "Owned overlay identity is not a content hash");
        return value;
    }
    inline fs::path nativeRelativePath(const DWUpdateAssetEntry &entry)
    {
        const auto value = name(entry);
        const std::string_view prefix(value.data(), value.find("dw_bot_styles_mp_"));
        for (const auto &rule : s_dwUpdateAssetFolderRules)
        {
            if (prefix != rule.prefix)
                continue;
            const fs::path directory = rule.directory;
            require(directory.empty() || (!directory.is_absolute() &&
                        directory.parent_path().empty() && directory != "." && directory != ".."),
                    "Invalid native overlay folder policy");
            return directory / value;
        }
        throw std::runtime_error("Owned overlay has no native folder policy");
    }
    inline std::vector<DWUpdateAssetEntry> manifest(const IO &io, std::span<const uint8_t> image)
    {
        constexpr uint8_t magic[16] = {'R','E','P','L','A','Y','D','W','A','S','S','E','T','0','1',0};
        std::vector<DWUpdateAssetEntry> result;
        Digest bundle{};
        bool found = false;
        for (size_t at = 0; at + sizeof(DWUpdateAssetHeader) <= image.size(); ++at)
        {
            if (std::memcmp(image.data() + at, magic, sizeof(magic)))
                continue;
            DWUpdateAssetHeader header{};
            std::memcpy(&header, image.data() + at, sizeof(header));
            if (header.version != DW_UPDATE_ASSET_VERSION || header.reserved || !header.count ||
                header.count > DW_UPDATE_ASSET_MAX_FILES ||
                header.bytes != sizeof(header) + header.count * sizeof(DWUpdateAssetEntry) ||
                header.bytes > image.size() - at)
                continue; // The helper also contains the parser's magic constant.
            require(!found, "Multiple owned asset manifests in verified executable");
            const auto payload = image.subspan(at + sizeof(header), header.bytes - sizeof(header));
            Bytes authenticated(std::begin(header.bundleHash), std::end(header.bundleHash));
            authenticated.insert(authenticated.end(), payload.begin(), payload.end());
            require(matches(io, authenticated, header.entriesHash), "Embedded asset manifest hash failed");
            std::copy(std::begin(header.bundleHash), std::end(header.bundleHash), bundle.begin());
            found = true;
            result.resize(header.count);
            std::memcpy(result.data(), payload.data(), payload.size());
        }
        if (!found)
            return result; // Complete updates to older releases remain compatible.
        std::set<std::string> names;
        std::map<std::wstring, uint64_t> payloads;
        std::string zone;
        for (const auto &entry : result)
        {
            const auto value = name(entry);
            nativeRelativePath(entry);
            require(entry.bytes && entry.bytes <= DW_UPDATE_ASSET_MAX_BYTES && names.insert(value).second,
                    "Duplicate or oversized owned asset");
            const auto digest = hex(entry.hash);
            auto [where, inserted] = payloads.emplace(digest, entry.bytes);
            require(inserted || where->second == entry.bytes, "Inconsistent owned payload size");
            if (value.starts_with("dw_bot_styles_mp_") && value.ends_with(".ff"))
            {
                require(zone.empty(), "Multiple primary overlay zones");
                zone = value.substr(0, value.size() - 3);
                require(zone.substr(zone.size() - 16) == asciiHex(bundle.data()).substr(0, 16),
                        "Owned zone identity does not match its complete bundle");
            }
        }
        require(!zone.empty() && payloads.size() <= 4, "Missing primary or invalid overlay payload set");
        for (const auto &value : names)
        {
            require(value.substr(value.size() - zone.size() - 3, zone.size()) == zone &&
                        names.contains(value.substr(0, value.size() - 3) + (value.ends_with(".ff") ? ".fp" : ".ff")),
                    "Mismatched or incomplete owned FF/FP pair");
        }
        return result;
    }

    class Session
    {
        struct Undo
        {
            fs::path destination, backup;
            Digest original{}, installed{};
            bool existed;
        };
        IO io;
        fs::path zone, folder, cache, backups;
        std::vector<DWUpdateAssetEntry> entries;
        std::vector<Undo> undo;
        bool committed = false;

        fs::path destination(const DWUpdateAssetEntry &entry) const
        {
            const auto relative = nativeRelativePath(entry);
            const auto parent = zone / relative.parent_path();
            const auto path = parent / relative.filename();
            require(parent == zone || parent.parent_path() == zone,
                    "Asset destination escaped native zone folders");
            safePath(zone); safePath(parent); safePath(path);
            return path;
        }
        fs::path blob(const DWUpdateAssetEntry &entry) const
        {
            const auto path = cache / (hex(entry.hash) + L".bin");
            safePath(path);
            return path;
        }
        bool validFile(const fs::path &path, const DWUpdateAssetEntry &entry) const
        {
            safePath(path);
            return fs::is_regular_file(path) && fs::file_size(path) == entry.bytes &&
                   matches(io, io.read(path, DW_UPDATE_ASSET_MAX_BYTES), entry.hash);
        }
        void roots(bool install)
        {
            safePath(folder.parent_path());
            directory(folder);
            directory(folder / "asset-staging"); directory(cache);
            if (install)
            {
                directory(zone);
                for (const auto &entry : entries)
                    directory((zone / nativeRelativePath(entry)).parent_path());
                directory(folder / "asset-backups"); directory(backups);
            }
        }
    public:
        Session(const IO &backend, const fs::path &exe, const fs::path &updateFolder,
                std::span<const uint8_t> verifiedImage, const uint8_t *targetHash)
            : io(backend), zone(exe.parent_path() / "zone"), folder(updateFolder),
              cache(folder / "asset-staging" / hex(targetHash)),
              backups(folder / "asset-backups" / hex(targetHash)), entries(manifest(io, verifiedImage))
        {
            require(exe.parent_path() == folder.parent_path(), "Asset staging escaped game root");
        }
        ~Session()
        {
            if (!committed && !undo.empty())
                try { rollback(); }
                catch (const std::exception &error)
                { std::ofstream(folder / "asset-rollback-errors.log", std::ios::app) << error.what() << '\n'; }
        }
        bool needed() const
        {
            for (const auto &entry : entries)
                if (!validFile(destination(entry), entry))
                    return true;
            return false;
        }
        void stage(const std::wstring &host)
        {
            if (!needed())
                return;
            roots(false);
            for (const auto &entry : entries)
            {
                if (validFile(destination(entry), entry) || validFile(blob(entry), entry))
                    continue;
                const auto bytes = io.download(host, L"/updates/v2/asset/" + hex(entry.hash), {}, entry.bytes);
                require(bytes.size() == entry.bytes && matches(io, bytes, entry.hash), "Downloaded owned asset hash failed");
                io.write(blob(entry), bytes);
                require(validFile(blob(entry), entry), "Staged owned asset hash failed");
            }
            verifyStage();
        }
        void verifyStage() const
        {
            safePath(folder); safePath(folder / "asset-staging"); safePath(cache);
            for (const auto &entry : entries)
                require(validFile(destination(entry), entry) || validFile(blob(entry), entry),
                        "Owned overlay asset is not completely staged");
        }
        void install()
        {
            if (!needed())
                return;
            verifyStage(); roots(true);
            try
            {
                for (const auto &entry : entries)
                {
                    const auto path = destination(entry);
                    if (validFile(path, entry))
                        continue;
                    Undo recovery{path, {}, {}, {}, fs::exists(path)};
                    std::copy(std::begin(entry.hash), std::end(entry.hash), recovery.installed.begin());
                    if (recovery.existed)
                    {
                        require(fs::is_regular_file(path), "Owned overlay destination is not a file");
                        const auto original = io.read(path, DW_UPDATE_ASSET_MAX_BYTES);
                        recovery.original = io.hash(original);
                        recovery.backup = backups / (std::to_wstring(undo.size()) + L"-" + hex(recovery.original.data()) + L".bak");
                        safePath(recovery.backup);
                        if (!fs::exists(recovery.backup))
                            io.write(recovery.backup, original);
                        require(matches(io, io.read(recovery.backup, DW_UPDATE_ASSET_MAX_BYTES), recovery.original.data()) &&
                                    matches(io, io.read(path, DW_UPDATE_ASSET_MAX_BYTES), recovery.original.data()),
                                "Existing overlay backup failed verification");
                        const auto journal = backups / L"recovery.tsv";
                        safePath(journal);
                        auto record = fs::exists(journal) ? io.read(journal, 1024 * 1024) : Bytes{};
                        const auto originalHash = asciiHex(recovery.original.data());
                        const auto line = nativeRelativePath(entry).generic_string() + '\t' + recovery.backup.filename().string() + '\t' +
                                          originalHash + '\n';
                        record.insert(record.end(), line.begin(), line.end());
                        io.write(journal, record);
                        require(io.read(journal, 1024 * 1024) == record, "Overlay recovery journal failed verification");
                    }
                    const auto temporary = cache / (L"install-" + std::to_wstring(undo.size()) + L".tmp");
                    safePath(temporary);
                    const auto bytes = io.read(blob(entry), DW_UPDATE_ASSET_MAX_BYTES);
                    require(matches(io, bytes, entry.hash), "Owned asset changed before replacement");
                    io.write(temporary, bytes);
                    require(validFile(temporary, entry), "Temporary owned asset failed verification");
                    undo.push_back(recovery);
                    if (recovery.existed)
                        require(ReplaceFileW(path.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr) != 0,
                                "Atomic overlay replacement failed; backup retained");
                    else
                        require(MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
                                "Atomic overlay installation failed");
                    require(validFile(path, entry), "Installed owned overlay failed verification");
                }
            }
            catch (...)
            {
                rollback();
                throw;
            }
        }
        void rollback()
        {
            for (auto item = undo.rbegin(); item != undo.rend(); ++item)
            {
                safePath(zone); safePath(item->destination.parent_path()); safePath(item->destination);
                if (item->existed)
                {
                    safePath(item->backup);
                    const auto original = io.read(item->backup, DW_UPDATE_ASSET_MAX_BYTES);
                    require(matches(io, original, item->original.data()), "Overlay recovery backup changed");
                    if (fs::exists(item->destination) && matches(io, io.read(item->destination, DW_UPDATE_ASSET_MAX_BYTES), item->original.data()))
                        continue;
                    require(!fs::exists(item->destination) || matches(io, io.read(item->destination, DW_UPDATE_ASSET_MAX_BYTES), item->installed.data()),
                            "Overlay changed externally; recovery copy retained");
                    const auto temporary = cache / L"rollback.tmp";
                    safePath(temporary); io.write(temporary, original);
                    require(fs::exists(item->destination)
                                ? ReplaceFileW(item->destination.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr) != 0
                                : MoveFileExW(temporary.c_str(), item->destination.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
                            "Overlay rollback failed; recovery backup retained");
                    require(matches(io, io.read(item->destination, DW_UPDATE_ASSET_MAX_BYTES), item->original.data()),
                            "Restored overlay failed verification");
                }
                else if (fs::exists(item->destination))
                {
                    require(matches(io, io.read(item->destination, DW_UPDATE_ASSET_MAX_BYTES), item->installed.data()),
                            "New overlay changed externally; file retained");
                    require(DeleteFileW(item->destination.c_str()) != 0, "Cannot roll back newly installed overlay");
                }
            }
            undo.clear();
        }
        void commit() { committed = true; undo.clear(); }
    };
} // namespace update_assets
