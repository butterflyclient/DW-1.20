#pragma once
#include "../integration/replay/dw_update_assets_protocol.h"
#include "../integration/replay/dw_update_maps_protocol.h"
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
        Bytes (*decompress)(std::span<const uint8_t>, uint32_t) = nullptr;
    };
    inline void require(bool condition, const char *message)
    {
        if (!condition)
            throw std::runtime_error(message);
    }
    inline void requireWin32(bool condition, const char *message)
    {
        if (!condition)
        {
            const auto error = GetLastError();
            throw std::runtime_error(std::string(message) + " (Windows error " + std::to_string(error) + ")");
        }
    }
    inline fs::path nativePath(const fs::path &input)
    {
        // Hash-addressed staging filenames exceed MAX_PATH even when the game
        // itself has a conventional path. Extended paths do not depend on the
        // process manifest or the owner's LongPathsEnabled registry setting.
        auto absolute = fs::absolute(input).lexically_normal();
        absolute.make_preferred();
        const auto value = absolute.native();
        require(value.size() < 32759 && !value.starts_with(L"\\\\.\\"), "Invalid native update path");
        if (value.starts_with(L"\\\\?\\"))
        {
            require((value.size() > 6 && value[5] == L':' && value[6] == L'\\') ||
                        value.starts_with(L"\\\\?\\UNC\\"), "Unsupported native update device path");
            return absolute;
        }
        if (value.starts_with(L"\\\\"))
            return fs::path(L"\\\\?\\UNC\\" + value.substr(2));
        require(value.size() > 2 && value[1] == L':' && value[2] == L'\\',
                "Update path is not an absolute Windows file path");
        return fs::path(L"\\\\?\\" + value);
    }
    // Best-effort removal of transient download files. Only plain files directly
    // inside the directory are deleted (optionally by name prefix); reparse points
    // are never followed. With no prefix the emptied directory is removed too.
    inline void purgeStaging(const fs::path &directoryPath, std::wstring_view prefix = {}) noexcept
    {
        try
        {
            const auto native = nativePath(directoryPath);
            const auto flags = GetFileAttributesW(native.c_str());
            if (flags == INVALID_FILE_ATTRIBUTES || !(flags & FILE_ATTRIBUTE_DIRECTORY) ||
                (flags & FILE_ATTRIBUTE_REPARSE_POINT))
                return;
            std::vector<fs::path> victims;
            std::error_code error;
            for (fs::directory_iterator item(native, error), end; !error && item != end; item.increment(error))
            {
                const auto name = item->path().filename().wstring();
                if (!prefix.empty() && !name.starts_with(prefix))
                    continue;
                const auto itemFlags = GetFileAttributesW(item->path().c_str());
                if (itemFlags != INVALID_FILE_ATTRIBUTES &&
                    !(itemFlags & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                    victims.push_back(item->path());
            }
            for (const auto &victim : victims)
                DeleteFileW(victim.c_str());
            if (prefix.empty())
                RemoveDirectoryW(native.c_str());
        }
        catch (...)
        {
        }
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
        const auto native = nativePath(path);
        const auto flags = GetFileAttributesW(native.c_str());
        if (flags != INVALID_FILE_ATTRIBUTES)
            require(!(flags & FILE_ATTRIBUTE_REPARSE_POINT), "Asset update path is a reparse point");
        else
        {
            const auto error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                throw std::runtime_error("Asset update path cannot be inspected (Windows error " + std::to_string(error) + ")");
        }
    }
    inline void directory(const fs::path &path)
    {
        const auto native = nativePath(path);
        safePath(native);
        if (!fs::exists(native))
            fs::create_directory(native);
        require(fs::is_directory(native), "Asset update directory is unavailable");
        safePath(native);
    }
    inline std::string_view ownerPrefix(unsigned owner)
    {
        require(owner == 1 || owner == 2, "Unknown owned overlay group");
        return owner == 1 ? "dw_bot_styles_mp_" : "dw_weapon_inspect_mp_";
    }
    inline std::string name(const DWUpdateAssetEntry &entry, unsigned owner = 0)
    {
        const auto end = std::find(std::begin(entry.name), std::end(entry.name), '\0');
        require(end != std::end(entry.name) && std::all_of(end, std::end(entry.name), [](char c) { return c == 0; }),
                "Invalid owned asset name padding");
        std::string value(entry.name, end);
        if (!owner)
            owner = value.find(ownerPrefix(1)) != std::string::npos ? 1 : 2;
        const auto prefix = ownerPrefix(owner);
        const auto at = value.find(prefix);
        require(at != std::string::npos && at <= 17 &&
                    (at == 0 || value[at - 1] == '_') &&
                    std::all_of(value.begin(), value.begin() + at, [](char c)
                    { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; }) &&
                    value.size() == at + prefix.size() + 16 + 3 &&
                    (value.ends_with(".ff") || value.ends_with(".fp")),
                "Asset manifest attempts to replace a shipped or non-zone file");
        const auto begin = value.begin() + at + prefix.size();
        require(std::all_of(begin, begin + 16, [](char c)
                { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }),
                "Owned overlay identity is not a content hash");
        return value;
    }
    inline fs::path nativeRelativePath(const DWUpdateAssetEntry &entry)
    {
        const auto value = name(entry);
        const auto owner = value.find(ownerPrefix(1)) != std::string::npos ? 1 : 2;
        const std::string_view prefix(value.data(), value.find(ownerPrefix(owner)));
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
    inline void validateGroup(const std::vector<DWUpdateAssetEntry> &entries,
                              unsigned owner, const uint8_t *bundle)
    {
        std::set<std::string> names;
        std::map<std::wstring, uint64_t> payloads;
        std::string zone;
        require(!entries.empty(), "Empty owned overlay group");
        for (const auto &entry : entries)
        {
            const auto value = name(entry, owner);
            nativeRelativePath(entry);
            require(entry.bytes && entry.bytes <= DW_UPDATE_ASSET_MAX_BYTES && names.insert(value).second,
                    "Duplicate or oversized owned asset");
            const auto digest = hex(entry.hash);
            auto [where, inserted] = payloads.emplace(digest, entry.bytes);
            require(inserted || where->second == entry.bytes, "Inconsistent owned payload size");
            if (value.starts_with(ownerPrefix(owner)) && value.ends_with(".ff"))
            {
                require(zone.empty(), "Multiple primary overlay zones");
                zone = value.substr(0, value.size() - 3);
                require(zone.substr(zone.size() - 16) == asciiHex(bundle).substr(0, 16),
                        "Owned zone identity does not match its complete bundle");
            }
        }
        require(!zone.empty() && payloads.size() <= 4, "Missing primary or invalid overlay payload set");
        for (const auto &value : names)
        {
            require(value.size() >= zone.size() + 3 &&
                        value.substr(value.size() - zone.size() - 3, zone.size()) == zone &&
                        names.contains(value.substr(0, value.size() - 3) + (value.ends_with(".ff") ? ".fp" : ".ff")),
                    "Mismatched or incomplete owned FF/FP pair");
        }
    }
    inline std::vector<DWUpdateAssetEntry> manifest(const IO &io, std::span<const uint8_t> image)
    {
        constexpr uint8_t magic[16] = {'R','E','P','L','A','Y','D','W','A','S','S','E','T','0','1',0};
        std::vector<DWUpdateAssetEntry> legacy, aggregate, aggregateBot;
        Digest legacyBundle{}, aggregateBotBundle{};
        bool foundLegacy = false, foundAggregate = false;
        for (size_t at = 0; at + sizeof(DWUpdateAssetHeader) <= image.size(); ++at)
        {
            if (std::memcmp(image.data() + at, magic, 14) || image[at + 15] ||
                    (image[at + 14] != '1' && image[at + 14] != '2'))
                continue;
            DWUpdateAssetHeader header{};
            std::memcpy(&header, image.data() + at, sizeof(header));
            const bool v2 = image[at + 14] == '2';
            const auto groups = v2 ? DW_UPDATE_ASSET_GROUPS : 0;
            if (header.version != (v2 ? DW_UPDATE_ASSET_AGGREGATE_VERSION : DW_UPDATE_ASSET_VERSION) ||
                header.reserved != groups || !header.count || header.count > DW_UPDATE_ASSET_MAX_FILES ||
                header.bytes != sizeof(header) + header.count * sizeof(DWUpdateAssetEntry) + groups * sizeof(DWUpdateAssetGroup) ||
                header.bytes > image.size() - at)
                continue; // Parser constants are not embedded manifest records.
            require(!(v2 ? foundAggregate : foundLegacy), "Multiple owned asset manifests in verified executable");
            const auto payload = image.subspan(at + sizeof(header), header.bytes - sizeof(header));
            Bytes authenticated(std::begin(header.bundleHash), std::end(header.bundleHash));
            authenticated.insert(authenticated.end(), payload.begin(), payload.end());
            require(matches(io, authenticated, header.entriesHash), "Embedded asset manifest hash failed");
            if (!v2)
            {
                legacy.resize(header.count);
                std::memcpy(legacy.data(), payload.data(), payload.size());
                validateGroup(legacy, 1, header.bundleHash);
                std::copy(std::begin(header.bundleHash), std::end(header.bundleHash), legacyBundle.begin());
                foundLegacy = true;
                continue;
            }
            size_t offset = 0, total = 0;
            Bytes descriptors;
            for (unsigned owner = 1; owner <= DW_UPDATE_ASSET_GROUPS; ++owner)
            {
                require(payload.size() - offset >= sizeof(DWUpdateAssetGroup), "Truncated owned group descriptor");
                DWUpdateAssetGroup group{};
                std::memcpy(&group, payload.data() + offset, sizeof(group));
                require(group.owner == owner && group.count && group.count <= header.count - total,
                        "Unknown, duplicate or unordered owned group");
                descriptors.insert(descriptors.end(), payload.begin() + offset, payload.begin() + offset + sizeof(group));
                offset += sizeof(group);
                const auto bytes = group.count * sizeof(DWUpdateAssetEntry);
                require(bytes <= payload.size() - offset, "Truncated owned group entries");
                std::vector<DWUpdateAssetEntry> entries(group.count);
                std::memcpy(entries.data(), payload.data() + offset, bytes);
                validateGroup(entries, owner, group.bundleHash);
                if (owner == 1)
                {
                    aggregateBot = entries;
                    std::copy(std::begin(group.bundleHash), std::end(group.bundleHash), aggregateBotBundle.begin());
                }
                aggregate.insert(aggregate.end(), entries.begin(), entries.end());
                offset += bytes;
                total += group.count;
            }
            require(offset == payload.size() && total == header.count && matches(io, descriptors, header.bundleHash),
                    "Aggregate owned group identity failed");
            foundAggregate = true;
        }
        if (!foundAggregate)
            return legacy; // Includes complete updates to releases without any manifest.
        require(foundLegacy && legacyBundle == aggregateBotBundle && legacy.size() == aggregateBot.size() &&
                    std::memcmp(legacy.data(), aggregateBot.data(), legacy.size() * sizeof(DWUpdateAssetEntry)) == 0,
                "Aggregate manifest lacks its exact legacy catch-up group");
        std::map<std::wstring, uint64_t> payloads;
        for (const auto &entry : aggregate)
        {
            const auto [where, inserted] = payloads.emplace(hex(entry.hash), entry.bytes);
            require(inserted || where->second == entry.bytes, "Inconsistent cross-group payload size");
        }
        return aggregate;
    }

    #include "replay-update-maps.h"

    class Session
    {
        struct File
        {
            fs::path relative;
            Digest hash{};
            uint64_t bytes, limit;
            const DWUpdateMapFile *map = nullptr;
        };
        struct Undo
        {
            fs::path destination, backup;
            Digest original{}, installed{};
            uint64_t originalBytes = 0, installedBytes = 0, limit = 0;
            bool existed;
        };
        IO io;
        fs::path game, folder, cache, backups;
        Maps maps;
        std::vector<File> files;
        std::vector<Undo> undo;
        bool committed = false;

        fs::path destination(const File &entry) const
        {
            fs::path path = game;
            safePath(path);
            for (const auto &part : entry.relative)
            {
                path /= part;
                safePath(path);
            }
            return path;
        }
        fs::path blob(const File &entry) const
        {
            const auto path = cache / ((entry.map ? L"map-" : L"") + hex(entry.hash.data()) + L".bin");
            safePath(path);
            return path;
        }
        bool validFile(const fs::path &path, const File &entry) const
        {
            if (entry.map)
                return fileMatches(path, entry.bytes, entry.hash.data(), entry.limit);
            safePath(path);
            return fs::is_regular_file(path) && fs::file_size(path) == entry.bytes &&
                   matches(io, io.read(path, entry.limit), entry.hash.data());
        }
        void roots(bool install)
        {
            safePath(game);
            directory(folder);
            directory(folder / "asset-staging"); directory(cache);
            if (install)
            {
                for (const auto &entry : files)
                {
                    fs::path parent = game;
                    for (const auto &part : entry.relative.parent_path())
                    {
                        parent /= part;
                        directory(parent);
                    }
                }
                directory(folder / "asset-backups"); directory(backups);
            }
        }
        void stageMap(const File &entry, const std::wstring &host)
        {
            require(io.decompress != nullptr, "Native map decompressor is unavailable");
            const auto partial = cache / (L"partial-" + hex(entry.hash.data()) + L".bin");
            safePath(partial);
            const auto handle = CreateFileW(partial.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
            requireWin32(handle != INVALID_HANDLE_VALUE, "Cannot stage map");
            bool open = true;
            try
            {
                const auto &file = *entry.map;
                for (uint32_t index = 0; index < file.chunkCount; ++index)
                {
                    const auto &chunk = maps.chunks[file.firstChunk + index];
                    const auto payloadPath = cache / (L"chunk-" + hex(chunk.payloadHash) + L".bin");
                    safePath(payloadPath);
                    Bytes compressed;
                    if (fs::is_regular_file(payloadPath) && fs::file_size(payloadPath) == chunk.payloadBytes)
                        compressed = io.read(payloadPath, DW_UPDATE_MAP_MAX_TRANSPORT_BYTES);
                    if (compressed.size() != chunk.payloadBytes || !matches(io, compressed, chunk.payloadHash))
                    {
                        compressed = io.download(host, L"/updates/v2/asset/" + hex(chunk.payloadHash), {}, chunk.payloadBytes);
                        require(compressed.size() == chunk.payloadBytes && matches(io, compressed, chunk.payloadHash),
                                "Downloaded compressed map chunk hash failed");
                        io.write(payloadPath, compressed);
                    }
                    // The untrusted transport hash is checked before Cabinet sees bytes.
                    const auto raw = io.decompress(compressed, chunk.bytes);
                    require(raw.size() == chunk.bytes && matches(io, raw, chunk.hash),
                            "Decompressed map chunk hash or size failed");
                    DWORD written = 0;
                    requireWin32(WriteFile(handle, raw.data(), static_cast<DWORD>(raw.size()), &written, nullptr) != 0,
                                 "Map staging write failed; installed files are unchanged");
                    require(written == raw.size(), "Map staging write was incomplete; installed files are unchanged");
                }
                requireWin32(FlushFileBuffers(handle) != 0, "Cannot flush staged map");
                requireWin32(CloseHandle(handle) != 0, "Cannot close staged map"); open = false;
                require(validFile(partial, entry), "Complete staged map file hash failed");
                requireWin32(MoveFileExW(partial.c_str(), blob(entry).c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0,
                        "Cannot publish staged map file");
            }
            catch (...)
            {
                if (open) CloseHandle(handle);
                // An incomplete raw file is never reused as a verified file.
                throw;
            }
        }
        void remember(Undo &recovery, const File &entry)
        {
            if (!recovery.existed)
                return;
            require(fs::is_regular_file(recovery.destination), "Asset destination is not a file");
            recovery.originalBytes = fs::file_size(recovery.destination);
            recovery.original = fileHash(recovery.destination, entry.limit);
            recovery.backup = backups / (std::to_wstring(undo.size()) + L"-" + hex(recovery.original.data()) + L".bak");
            safePath(recovery.backup);
            if (!fs::exists(recovery.backup))
            {
                if (entry.map)
                    verifiedCopy(recovery.destination, recovery.backup, recovery.originalBytes, recovery.original.data(), entry.limit);
                else
                    io.write(recovery.backup, io.read(recovery.destination, entry.limit));
            }
            require(fileMatches(recovery.backup, recovery.originalBytes, recovery.original.data(), entry.limit) &&
                        fileMatches(recovery.destination, recovery.originalBytes, recovery.original.data(), entry.limit),
                    "Existing asset backup failed verification");
            const auto journal = backups / L"recovery.tsv";
            safePath(journal);
            auto record = fs::exists(journal) ? io.read(journal, 1024 * 1024) : Bytes{};
            const auto line = entry.relative.generic_string() + '\t' + recovery.backup.filename().string() + '\t' +
                              asciiHex(recovery.original.data()) + '\n';
            record.insert(record.end(), line.begin(), line.end());
            io.write(journal, record);
            require(io.read(journal, 1024 * 1024) == record, "Asset recovery journal failed verification");
        }
    public:
        Session(const IO &backend, const fs::path &exe, const fs::path &updateFolder,
                std::span<const uint8_t> verifiedImage, const uint8_t *targetHash)
            : io(backend), game(nativePath(exe).parent_path()), folder(nativePath(updateFolder)),
              cache(folder / "asset-staging" / hex(targetHash)),
              backups(folder / "asset-backups" / hex(targetHash)), maps(mapManifest(io, verifiedImage))
        {
            require(game == folder.parent_path(), "Asset staging escaped game root");
            for (const auto &entry : manifest(io, verifiedImage))
            {
                File file{fs::path("zone") / nativeRelativePath(entry), {}, entry.bytes, DW_UPDATE_ASSET_MAX_BYTES};
                std::copy(std::begin(entry.hash), std::end(entry.hash), file.hash.begin());
                files.push_back(file);
            }
            for (const auto &entry : maps.files)
            {
                File file{mapPath(entry), {}, entry.bytes, DW_UPDATE_MAP_MAX_FILE_BYTES, &entry};
                std::copy(std::begin(entry.hash), std::end(entry.hash), file.hash.begin());
                files.push_back(file);
            }
        }
        ~Session()
        {
            if (!committed && !undo.empty())
                try { rollback(); }
                catch (const std::exception &error)
                { std::ofstream(folder / "asset-rollback-errors.log", std::ios::app) << error.what() << '\n'; }
        }
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;
        bool needed() const
        {
            for (const auto &entry : files)
                if (!validFile(destination(entry), entry))
                    return true;
            return false;
        }
        void stage(const std::wstring &host)
        {
            if (!needed())
                return;
            roots(false);
            for (const auto &entry : files)
            {
                if (validFile(destination(entry), entry) || validFile(blob(entry), entry))
                    continue;
                if (entry.map)
                    stageMap(entry, host);
                else
                {
                    const auto bytes = io.download(host, L"/updates/v2/asset/" + hex(entry.hash.data()), {}, entry.bytes);
                    require(bytes.size() == entry.bytes && matches(io, bytes, entry.hash.data()), "Downloaded owned asset hash failed");
                    io.write(blob(entry), bytes);
                    require(validFile(blob(entry), entry), "Staged owned asset hash failed");
                }
            }
            verifyStage();
            // Compressed chunks are only transport; the verified raw blobs remain
            // until installation.
            purgeStaging(cache, L"chunk-");
            purgeStaging(cache, L"partial-");
        }
        void verifyStage() const
        {
            safePath(folder); safePath(folder / "asset-staging"); safePath(cache);
            for (const auto &entry : files)
                require(validFile(destination(entry), entry) || validFile(blob(entry), entry),
                        "Owned asset or map is not completely staged");
        }
        void install()
        {
            if (!needed())
                return;
            verifyStage(); roots(true);
            try
            {
                for (const auto &entry : files)
                {
                    const auto path = destination(entry);
                    if (validFile(path, entry))
                        continue;
                    Undo recovery{path, {}, {}, {}, 0, entry.bytes, entry.limit, fs::exists(path)};
                    recovery.installed = entry.hash;
                    remember(recovery, entry);
                    const auto temporary = cache / (L"install-" + std::to_wstring(undo.size()) + L".tmp");
                    safePath(temporary);
                    if (entry.map)
                        verifiedCopy(blob(entry), temporary, entry.bytes, entry.hash.data(), entry.limit);
                    else
                    {
                        const auto bytes = io.read(blob(entry), entry.limit);
                        require(matches(io, bytes, entry.hash.data()), "Owned asset changed before replacement");
                        io.write(temporary, bytes);
                        require(validFile(temporary, entry), "Temporary owned asset failed verification");
                    }
                    undo.push_back(recovery);
                    if (recovery.existed)
                        requireWin32(ReplaceFileW(path.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr) != 0,
                                "Atomic asset replacement failed; backup retained");
                    else
                        requireWin32(MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
                                "Atomic asset installation failed");
                    require(validFile(path, entry), "Installed owned asset failed verification");
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
                fs::path ancestor = game;
                safePath(ancestor);
                for (const auto &part : item->destination.lexically_relative(game).parent_path())
                {
                    ancestor /= part; safePath(ancestor);
                }
                safePath(item->destination);
                if (item->existed)
                {
                    safePath(item->backup);
                    require(fileMatches(item->backup, item->originalBytes, item->original.data(), item->limit),
                            "Asset recovery backup changed");
                    if (fileMatches(item->destination, item->originalBytes, item->original.data(), item->limit))
                        continue;
                    require(!fs::exists(item->destination) || fileMatches(item->destination, item->installedBytes, item->installed.data(), item->limit),
                            "Asset changed externally; recovery copy retained");
                    const auto temporary = cache / L"rollback.tmp";
                    verifiedCopy(item->backup, temporary, item->originalBytes, item->original.data(), item->limit);
                    requireWin32(fs::exists(item->destination)
                                ? ReplaceFileW(item->destination.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr) != 0
                                : MoveFileExW(temporary.c_str(), item->destination.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
                            "Asset rollback failed; recovery backup retained");
                    require(fileMatches(item->destination, item->originalBytes, item->original.data(), item->limit),
                            "Restored asset failed verification");
                }
                else if (fs::exists(item->destination))
                {
                    require(fileMatches(item->destination, item->installedBytes, item->installed.data(), item->limit),
                            "New asset changed externally; file retained");
                    requireWin32(DeleteFileW(item->destination.c_str()) != 0, "Cannot roll back newly installed asset");
                }
            }
            undo.clear();
        }
        void commit()
        {
            committed = true;
            undo.clear();
            discardStaging();
        }
        // Drops every staged download (this target and stale older targets).
        // Backups under asset-backups are recovery data and are kept.
        void discardStaging() const noexcept
        {
            try
            {
                const auto root = nativePath(folder / "asset-staging");
                const auto flags = GetFileAttributesW(root.c_str());
                if (flags == INVALID_FILE_ATTRIBUTES || !(flags & FILE_ATTRIBUTE_DIRECTORY) ||
                    (flags & FILE_ATTRIBUTE_REPARSE_POINT))
                    return;
                std::vector<fs::path> targets;
                std::error_code error;
                for (fs::directory_iterator item(root, error), end; !error && item != end; item.increment(error))
                    targets.push_back(item->path());
                for (const auto &target : targets)
                    purgeStaging(target);
            }
            catch (...)
            {
            }
        }
    };
} // namespace update_assets
