#include "host_os.h"
#include "content_pack.h"
#include "crypto.h"
#include "platform.h"
#include "wire.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <ctime>
#include <vector>

namespace content_pack
{
    namespace
    {
        using Json = nlohmann::json;

        // Top-level data folders a pack may write. Everything else in a data
        // folder is player, session, key or machine state and is never packed.
        const std::set<std::string> publishedRoots = {
            "ab-testing",        "achievements",   "battlepass",          "geography.json",
            "inventory-validation", "leaderboard-definitions", "marketing", "marketplace",
            "objectstore",       "platform-word-filters.json", "playlists", "publisher-variables",
            "qos",               "relay",          "rest",                "scheduled-matches",
            "validated-stats",
        };

        std::string hex(std::span<const uint8_t> bytes)
        {
            constexpr char digits[] = "0123456789abcdef";
            std::string out;
            out.reserve(bytes.size() * 2);
            for (const auto value : bytes)
            {
                out.push_back(digits[value >> 4]);
                out.push_back(digits[value & 15]);
            }
            return out;
        }

        std::string sha256(const wire::Bytes &bytes)
        {
            return hex(crypto::sha256(bytes));
        }

        std::optional<wire::Bytes> read(const std::filesystem::path &path, uintmax_t limit)
        {
            if (!std::filesystem::is_regular_file(path))
                return std::nullopt;
            const auto size = std::filesystem::file_size(path);
            if (size > limit)
                throw std::runtime_error("Content pack file exceeds its size limit");
            std::ifstream input(path, std::ios::binary);
            wire::Bytes bytes(static_cast<size_t>(size));
            if (!input.read(reinterpret_cast<char *>(bytes.data()),
                            static_cast<std::streamsize>(bytes.size())))
                throw std::runtime_error("Content pack read failed");
            return bytes;
        }

        void write(const std::filesystem::path &path, std::span<const uint8_t> bytes)
        {
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Content pack persistence failed");
            {
                const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Content pack persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Content pack publication failed");
        }

        void writeJson(const std::filesystem::path &path, const Json &json)
        {
            const auto text = json.dump(2) + "\n";
            write(path, std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size()));
        }

        // A pack path stays inside the data folder and inside a published root:
        // forward slashes, no empty/./.. segments, the bounded filename alphabet.
        bool packPath(const std::string &relative)
        {
            if (relative.empty() || relative.size() > 240 || relative.front() == '/' ||
                relative.back() == '/')
                return false;
            size_t start = 0;
            std::vector<std::string> parts;
            while (start <= relative.size())
            {
                const auto end = relative.find('/', start);
                const auto part = relative.substr(
                    start, end == std::string::npos ? std::string::npos : end - start);
                if (part.empty() || part == "." || part == ".." || part.size() > 96)
                    return false;
                for (const auto c : part)
                    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
                        return false;
                parts.push_back(part);
                if (end == std::string::npos)
                    break;
                start = end + 1;
            }
            if (!publishedRoots.contains(parts.front()))
                return false;
            // Only publisher objects; user objects and the content cache are runtime state.
            if (parts.front() == "objectstore")
                return parts.size() == 6 && parts[1] == "publisher";
            if (parts.front() == "qos" || parts.front() == "relay")
                return parts.size() == 2 && parts[1] == "local-provider.json";
            return true;
        }

        std::string identifier(const Json &value, size_t capacity)
        {
            wire::require(value.is_string());
            const auto text = value.get<std::string>();
            wire::require(!text.empty() && text.size() < capacity &&
                          std::all_of(text.begin(),
                                      text.end(),
                                      [](char c)
                                      {
                                          return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                                 (c >= '0' && c <= '9') || c == '_' || c == '-' ||
                                                 c == '.';
                                      }));
            return text;
        }

        void installPack(const std::filesystem::path &data,
                         const std::filesystem::path &pack,
                         const Log &log)
        {
            const auto manifestBytes = read(pack / "manifest.json", 4 * 1024 * 1024);
            if (!manifestBytes)
                return;
            const auto manifest = Json::parse(manifestBytes->begin(), manifestBytes->end());
            wire::require(manifest.is_object() && manifest.at("schema") == 1 &&
                          manifest.at("files").is_object() && manifest["files"].size() <= 4096);
            const auto name = identifier(manifest.at("pack"), 64);
            const auto revision = manifest.at("revision").get<std::string>();
            const auto statePath = data / "content-packs" / (name + ".json");
            Json state = {{"schema", 1}, {"pack", name}, {"installed", Json::object()}};
            if (const auto stored = read(statePath, 4 * 1024 * 1024))
            {
                auto parsed = Json::parse(stored->begin(), stored->end(), nullptr, false);
                if (parsed.is_object() && parsed.value("schema", 0) == 1 &&
                    parsed.value("pack", "") == name && parsed.contains("installed") &&
                    parsed["installed"].is_object())
                    state = std::move(parsed);
            }
            auto &installed = state["installed"];
            unsigned added = 0, updated = 0, current = 0, kept = 0;
            for (const auto &[relative, entry] : manifest["files"].items())
            {
                if (!packPath(relative))
                    throw std::runtime_error("Content pack " + name + " names a non-content path");
                const auto expected = entry.at("sha256").get<std::string>();
                const auto source = read(pack / "files" / relative, 16 * 1024 * 1024);
                if (!source || source->size() != entry.at("bytes").get<uint64_t>() ||
                    sha256(*source) != expected)
                    throw std::runtime_error("Content pack " + name + " file is missing or corrupt");
                const auto destination = data / relative;
                const auto existing = read(destination, 64 * 1024 * 1024);
                if (!existing)
                {
                    write(destination, *source);
                    installed[relative] = expected;
                    ++added;
                    continue;
                }
                const auto present = sha256(*existing);
                if (present == expected)
                {
                    installed[relative] = expected;
                    ++current;
                }
                else if (installed.contains(relative) && installed[relative] == present)
                {
                    // Re-signed locally from exactly this pack file
                    // (signPatchManifests): the local signature is current.
                    if (state.contains("derived") && state["derived"].value(relative, "") == expected)
                    {
                        ++current;
                        continue;
                    }
                    // Still the bytes an earlier pack revision put there.
                    write(destination, *source);
                    installed[relative] = expected;
                    if (state.contains("derived"))
                        state["derived"].erase(relative);
                    ++updated;
                }
                else
                    // Published or edited on this server; the operator's copy wins.
                    ++kept;
            }
            state["revision"] = revision;
            state["build"] = manifest.value("build", "");
            state["titles"] = manifest.value("titles", Json::array());
            writeJson(statePath, state);
            log("CONTENT pack=" + name + " revision=" + revision.substr(0, 16) +
                " added=" + std::to_string(added) + " updated=" + std::to_string(updated) +
                " current=" + std::to_string(current) + " kept_local=" + std::to_string(kept));
        }

        Json fileRecord(const std::filesystem::path &path, const std::filesystem::path &root)
        {
            std::ifstream input(path, std::ios::binary);
            std::array<uint8_t, 16> header{};
            input.read(reinterpret_cast<char *>(header.data()), header.size());
            const auto count = static_cast<size_t>(input.gcount());
            Json record = {
                // Lexical: mods/mw120r/maps may be a junction to another drive.
                {"path", path.lexically_relative(root).generic_string()},
                {"bytes", static_cast<uint64_t>(std::filesystem::file_size(path))},
                {"header_sha256", hex(crypto::sha256(std::span(header.data(), count)))},
                {"complete_header", count == header.size()},
                {"magic", std::string(reinterpret_cast<const char *>(header.data()),
                                      std::min<size_t>(count, 8))},
            };
            if (count == header.size())
            {
                record["compression_version"] = wire::at<uint32_t>(header, 8);
                record["xfile_version"] = wire::at<uint32_t>(header, 12);
            }
            return record;
        }

        bool reparsePoint(const std::filesystem::path &path)
        {
#ifdef _WIN32
            const auto attributes = GetFileAttributesW(path.c_str());
            return attributes != INVALID_FILE_ATTRIBUTES &&
                   (attributes & FILE_ATTRIBUTE_REPARSE_POINT);
#else
            return std::filesystem::is_symlink(path);
#endif
        }

        // Same inventory as tools/playlist_packages.py: the declared playlist maps,
        // their primary FF header and presence. A DW custom map is a plain
        // mods/mw120r/maps/<id>/ folder (DW_MapAvailability.cpp skips reparse
        // points); stock packages are IWffa100 and zonetool builds IWffc100.
        Json inventory(const Json &catalog,
                       const std::string &catalogSha256,
                       uint32_t title,
                       const std::filesystem::path &game)
        {
            std::set<std::string> names;
            for (const auto &playlist : catalog.at("playlists"))
                for (const auto &entry : playlist.at("maps"))
                    names.insert(identifier(entry.at("map"), 24));
            Json maps = Json::array();
            for (const auto &name : names)
            {
                Json candidates = Json::array();
                const auto custom = game / "mods" / "mw120r" / "maps" / name;
                const std::array<std::filesystem::path, 4> folders = {
                    game, game / "zone", game / "main", custom};
                for (const auto &folder : folders)
                {
                    if (folder == custom && reparsePoint(custom))
                        continue;
                    const auto path = folder / (name + ".ff");
                    if (!std::filesystem::is_regular_file(path))
                        continue;
                    auto record = fileRecord(path, game);
                    for (const auto *suffix : {".fp", ".fc"})
                    {
                        auto companion = path;
                        companion.replace_extension(suffix);
                        if (std::filesystem::is_regular_file(companion))
                            record[suffix + 1] = fileRecord(companion, game);
                    }
                    candidates.push_back(std::move(record));
                }
                const Json primary = candidates.empty() ? Json() : candidates.front();
                // DW_MapAvailability.cpp accepts either header for a custom map folder.
                const bool customPackage =
                    !primary.is_null() && primary["path"].get<std::string>().starts_with("mods/");
                const bool available =
                    !primary.is_null() && primary["complete_header"] == true &&
                    primary["bytes"].get<uint64_t>() > 16 &&
                    (primary["magic"] == "IWffa100" || (customPackage && primary["magic"] == "IWffc100"));
                maps.push_back({{"name", name},
                                {"available", available},
                                {"status",
                                 available           ? "main-package-present"
                                 : primary.is_null() ? "main-package-absent"
                                                     : "unrecognized-package-header"},
                                {"primary", primary},
                                {"candidates", candidates}});
            }
            Json body = {
                {"schema", 1},
                {"title", title},
                {"playlist_version", catalog.at("system").at("version")},
                {"catalog_sha256", catalogSha256},
                {"maps", maps},
                {"scope", "Declared playlist maps; primary FF header/presence and optional FP/FC metadata"},
                {"native_map_load_verified", false},
                {"transient_completeness_verified", false},
            };
            const auto canonical = body.dump();
            body["revision"] = hex(crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(canonical.data()), canonical.size())));
            return body;
        }
    } // namespace

    void signPatchManifests(const std::filesystem::path &data, const Log &log)
    {
        const auto root = data / "objectstore" / "publisher";
        if (!std::filesystem::is_directory(root))
            return;
        for (const auto &entry : std::filesystem::recursive_directory_iterator(root))
        {
            const auto file = entry.path().filename().string();
            constexpr std::string_view suffix = ".txt.content.bin";
            if (!entry.is_regular_file() || !file.starts_with("1_manifest_") || !file.ends_with(suffix))
                continue;
            const auto bytes = read(entry.path(), 65536);
            auto manifest = Json::parse(bytes->begin(), bytes->end(), nullptr, false);
            if (!manifest.is_object() || manifest.value("count", -1) != 0 ||
                !manifest.contains("signature") || !manifest["signature"].is_string())
                continue;
            // Same-Replay manifest ABI (prepare-replay-publisher-content.py,
            // parser 0x14107AB50, verifier 0x141038500): SHA-256 over a zeroed
            // 901132-byte body whose header at 901120 is <u32 count, u16
            // manifestver, u16 dataverff, u16 purgeCache>; PSS salt 8 bytes.
            std::vector<uint8_t> body(901132);
            const auto put16 = [&](size_t offset, uint64_t value)
            {
                wire::require(value <= 0xFFFF);
                body[offset] = static_cast<uint8_t>(value);
                body[offset + 1] = static_cast<uint8_t>(value >> 8);
            };
            put16(901124, manifest.value("manifestver", uint64_t{0}));
            put16(901126, manifest.value("dataverff", uint64_t{0}));
            put16(901128, manifest.value("purgeCache", uint64_t{0}));
            const auto digest = crypto::sha256(body);
            const auto signatureHex = manifest["signature"].get<std::string>();
            std::vector<uint8_t> signature;
            for (size_t i = 0; i + 1 < signatureHex.size() && signature.size() < 257; i += 2)
                signature.push_back(static_cast<uint8_t>(std::stoul(signatureHex.substr(i, 2), nullptr, 16)));
            if (platform::verifyDigest(digest, signature, 8))
                continue;
            const auto fresh = platform::signDigest(digest, 8);
            manifest["signature"] = hex(fresh);
            const auto text = manifest.dump() + "\n";
            const wire::Bytes content(text.begin(), text.end());
            write(entry.path(), content);
            const auto name = file.substr(0, file.size() - std::string_view(".content.bin").size());
            const auto metadataPath = entry.path().parent_path() / (name + ".metadata.json");
            const auto present = read(metadataPath, 16384);
            if (present)
            {
                auto metadata = Json::parse(present->begin(), present->end());
                const auto md5 = crypto::md5(content);
                static constexpr char alphabet[] =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                std::string checksum;
                for (size_t i = 0; i < md5.size(); i += 3)
                {
                    const uint32_t chunk = (md5[i] << 16) | ((i + 1 < md5.size() ? md5[i + 1] : 0) << 8) |
                                           (i + 2 < md5.size() ? md5[i + 2] : 0);
                    checksum.push_back(alphabet[(chunk >> 18) & 63]);
                    checksum.push_back(alphabet[(chunk >> 12) & 63]);
                    checksum.push_back(i + 1 < md5.size() ? alphabet[(chunk >> 6) & 63] : '=');
                    checksum.push_back(i + 2 < md5.size() ? alphabet[chunk & 63] : '=');
                }
                metadata["contentLength"] = static_cast<uint64_t>(content.size());
                metadata["checksum"] = checksum;
                metadata["objectVersion"] = sha256(content).substr(0, 32);
                metadata["modified"] = static_cast<int64_t>(std::time(nullptr));
                writeJson(metadataPath, metadata);
            }
            // Pack state follows the re-signed bytes so a newer pack still applies.
            const auto relativeContent = entry.path().lexically_relative(data).generic_string();
            const auto relativeMetadata = metadataPath.lexically_relative(data).generic_string();
            const auto states = data / "content-packs";
            if (std::filesystem::is_directory(states))
                for (const auto &stateFile : std::filesystem::directory_iterator(states))
                {
                    const auto stored = read(stateFile.path(), 4 * 1024 * 1024);
                    auto state = Json::parse(stored->begin(), stored->end(), nullptr, false);
                    if (!state.is_object() || !state.contains("installed"))
                        continue;
                    bool changed = false;
                    for (const auto &[relative, path] : {std::pair{relativeContent, entry.path()},
                                                         std::pair{relativeMetadata, metadataPath}})
                        if (state["installed"].contains(relative))
                        {
                            // Remember the pack bytes this local signature replaced.
                            if (!state.contains("derived"))
                                state["derived"] = Json::object();
                            if (!state["derived"].contains(relative))
                                state["derived"][relative] = state["installed"][relative];
                            state["installed"][relative] = sha256(*read(path, 65536));
                            changed = true;
                        }
                    if (changed)
                        writeJson(stateFile.path(), state);
                }
            log("CONTENT re-signed patch manifest " + name + " with this server's platform key");
        }
    }

    std::optional<std::filesystem::path> locate()
    {
        std::filesystem::path executable;
#ifdef _WIN32
        std::wstring buffer(32768, L'\0');
        const auto size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!size || size >= buffer.size())
            return std::nullopt;
        buffer.resize(size);
        executable = buffer;
#else
        std::error_code error;
        executable = std::filesystem::read_symlink("/proc/self/exe", error);
        if (error)
            return std::nullopt;
#endif
        // build/Release/iw8-dw-server.exe, build/iw8-dw-server and a release
        // folder that carries content/ beside the binary.
        auto folder = executable.parent_path();
        for (int depth = 0; depth < 4 && !folder.empty(); ++depth)
        {
            const auto candidate = folder / "content";
            std::error_code error;
            if (std::filesystem::is_directory(candidate, error))
                for (const auto &entry : std::filesystem::directory_iterator(candidate, error))
                    if (std::filesystem::is_regular_file(entry.path() / "manifest.json", error))
                        return candidate;
            if (folder == folder.parent_path())
                break;
            folder = folder.parent_path();
        }
        return std::nullopt;
    }

    void install(const std::filesystem::path &data, const std::filesystem::path &root, const Log &log)
    {
        std::vector<std::filesystem::path> packs;
        for (const auto &entry : std::filesystem::directory_iterator(root))
            if (entry.is_directory() && std::filesystem::is_regular_file(entry.path() / "manifest.json"))
                packs.push_back(entry.path());
        std::sort(packs.begin(), packs.end());
        for (const auto &pack : packs)
            installPack(data, pack, log);
    }

    void prepareLocalPlay(const std::filesystem::path &data, bool loopbackOnly, const Log &log)
    {
        const auto keyPath = data / "operator-access.key";
        if (loopbackOnly && !std::filesystem::exists(keyPath))
        {
            // Dashboard start-match/fill-bot controls need an operator secret
            // (services::operatorStartMatch). A loopback server is only reachable
            // from this PC; the key is still never derived from client identity.
            const auto key = hex(crypto::random(32)) + "\n";
            write(keyPath, std::span(reinterpret_cast<const uint8_t *>(key.data()), key.size()));
            log("OPERATOR local dashboard key created in operator-access.key");
        }
        const auto configPath = data / "local-play.json";
        const auto config = read(configPath, 16384);
        if (!config)
            return;
        const auto json = Json::parse(config->begin(), config->end());
        wire::require(json.is_object() && json.at("schema") == 1);
        if (!json.contains("game_directory"))
            return;
        const std::filesystem::path game = json.at("game_directory").get<std::string>();
        if (!std::filesystem::is_directory(game))
        {
            log("LOCAL game_directory from local-play.json is not a folder; map inventory skipped");
            return;
        }
        const auto playlists = data / "playlists";
        if (!std::filesystem::is_directory(playlists))
            return;
        for (const auto &entry : std::filesystem::directory_iterator(playlists))
        {
            const auto folder = entry.path().filename().string();
            uint32_t title = 0;
            const auto parsed = std::from_chars(folder.data(), folder.data() + folder.size(), title);
            if (!entry.is_directory() || parsed.ec != std::errc{} ||
                parsed.ptr != folder.data() + folder.size())
                continue;
            const auto catalogBytes = read(entry.path() / "catalog.json", 409600);
            if (!catalogBytes)
                continue;
            const auto catalog = Json::parse(catalogBytes->begin(), catalogBytes->end());
            const auto body = inventory(catalog, sha256(*catalogBytes), title, game);
            const auto path = entry.path() / "packages.json";
            const auto existing = read(path, 512 * 1024);
            const auto text = body.dump(2) + "\n";
            if (existing && std::string(existing->begin(), existing->end()) == text)
                continue;
            write(path, std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size()));
            unsigned available = 0;
            for (const auto &map : body["maps"])
                available += map["available"].get<bool>();
            log("LOCAL title=" + folder + " installed playlist maps=" + std::to_string(available) +
                "/" + std::to_string(body["maps"].size()));
        }
    }
} // namespace content_pack
