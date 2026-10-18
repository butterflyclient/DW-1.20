#pragma once
#include "../integration/replay/dw_update_protocol.h"
#include "crypto.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace executable_updates
{
    inline bool digestName(const std::string &text)
    {
        return text.size() == 64 && std::all_of(text.begin(),
                                                text.end(),
                                                [](char c)
                                                {
                                                    return (c >= '0' && c <= '9') ||
                                                           (c >= 'a' && c <= 'f');
                                                });
    }

    inline std::string hex(const uint8_t *bytes)
    {
        std::string result;
        for (unsigned i = 0; i < 32; ++i)
        {
            result += "0123456789abcdef"[bytes[i] >> 4];
            result += "0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }

    inline void decode(const std::string &value, uint8_t *out)
    {
        if (!digestName(value))
            throw std::runtime_error("Invalid executable update digest");
        auto digit = [](char c)
        {
            return c <= '9' ? c - '0' : c - 'a' + 10;
        };
        for (unsigned i = 0; i < 32; ++i)
            out[i] = static_cast<uint8_t>((digit(value[i * 2]) << 4) | digit(value[i * 2 + 1]));
    }

    inline DWUpdatePlan plan(const std::filesystem::path &root,
                             const DWUpdateRequest &request,
                             uint64_t now)
    {
        if (request.magic != DW_UPDATE_MAGIC ||
            (request.version != 1 && request.version != 2) || request.reserved ||
            std::all_of(std::begin(request.nonce),
                        std::end(request.nonce),
                        [](uint8_t c)
                        {
                            return c == 0;
                        }))
            throw std::runtime_error("Invalid executable update request");
        DWUpdatePlan result{};
        result.magic = DW_UPDATE_MAGIC;
        result.version = request.version;
        result.status = 2;
        result.issued = now;
        result.expires = now + 86400;
        std::memcpy(result.nonce, request.nonce, 32);
        std::memcpy(result.baseHash, request.baseHash, 32);
        if (request.version == 2)
        {
            const auto index = root / "updates" / "full-image-catalog.json";
            if (!std::filesystem::exists(index))
                return result;
            if (std::filesystem::file_size(index) > 4096)
                throw std::runtime_error("Full executable catalog exceeds bounds");
            std::ifstream file(index);
            const auto catalog = nlohmann::json::parse(file);
            if (catalog.at("schema") != 1 || catalog.at("format") != "full-executable-v1")
                throw std::runtime_error("Unsupported full executable catalog");
            const auto latest = catalog.at("latest").get<std::string>();
            decode(latest, result.targetHash);
            result.targetSize = catalog.at("target_size").get<uint64_t>();
            result.release = catalog.at("release").get<uint64_t>();
            if (!result.targetSize || result.targetSize > DW_UPDATE_MAX_IMAGE ||
                !result.release ||
                std::filesystem::file_size(root / "updates" / "images" / (latest + ".exe")) !=
                    result.targetSize)
                throw std::runtime_error("Full executable is not completely published");
            if (hex(request.baseHash) == latest)
                result.status = 0;
            else
            {
                // A complete image needs no prior-build inventory. The signed
                // base hash still binds replacement to the player's unchanged EXE.
                result.status = 1;
                std::memcpy(result.patchHash, result.targetHash, 32);
                result.patchSize = result.targetSize;
            }
            return result;
        }
        const auto index = root / "updates" / "catalog.json";
        if (!std::filesystem::exists(index))
            return result;
        if (std::filesystem::file_size(index) > 4 * 1024 * 1024)
            throw std::runtime_error("Executable catalog exceeds bounds");
        std::ifstream file(index);
        const auto catalog = nlohmann::json::parse(file);
        if (catalog.at("schema") != 1 || catalog.at("format") != "msdelta-raw-v1")
            throw std::runtime_error("Unsupported executable catalog");
        const auto latest = catalog.at("latest").get<std::string>();
        decode(latest, result.targetHash);
        result.targetSize = catalog.at("target_size").get<uint64_t>();
        result.release = catalog.at("release").get<uint64_t>();
        if (!result.targetSize || result.targetSize > DW_UPDATE_MAX_IMAGE || !result.release)
            throw std::runtime_error("Invalid target executable bounds");
        const auto base = hex(request.baseHash);
        if (base == latest)
        {
            result.status = 0;
            result.baseSize = result.targetSize;
            return result;
        }
        const auto &patches = catalog.at("patches");
        if (!patches.contains(base))
            return result;
        const auto &entry = patches.at(base);
        result.baseSize = entry.at("base_size").get<uint64_t>();
        result.patchSize = entry.at("size").get<uint64_t>();
        const auto patch = entry.at("sha256").get<std::string>();
        decode(patch, result.patchHash);
        if (!result.baseSize || result.baseSize > DW_UPDATE_MAX_IMAGE || !result.patchSize ||
            result.patchSize > DW_UPDATE_MAX_IMAGE ||
            std::filesystem::file_size(root / "updates" / "patches" / (patch + ".delta")) !=
                result.patchSize)
            throw std::runtime_error("Executable patch is not completely published");
        result.status = 1;
        return result;
    }

    // ---- Signed release manifest (GET /updates/v2/manifest) ------------------------------
    // One document that describes the whole current release: the executable, the custom-map
    // manifest and the owned game-content (overlay) manifest. Everything is read from files the
    // existing publishers already commit (full-image-catalog.json and the hash-addressed
    // manifest blobs), re-verified here, and embedded so the signature covers the lot.

    constexpr size_t RELEASE_CATALOG_LIMIT = 4096;
    constexpr size_t RELEASE_MANIFEST_BLOB_LIMIT = 512 * 1024;
    constexpr size_t RELEASE_DOCUMENT_LIMIT = 2 * 1024 * 1024;
    constexpr uint64_t RELEASE_DOCUMENT_LIFETIME = 3600;

    inline std::string base64(const std::string &bytes)
    {
        constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve((bytes.size() + 2) / 3 * 4);
        for (size_t i = 0; i < bytes.size(); i += 3)
        {
            unsigned v = static_cast<unsigned>(static_cast<uint8_t>(bytes[i])) << 16;
            if (i + 1 < bytes.size())
                v |= static_cast<unsigned>(static_cast<uint8_t>(bytes[i + 1])) << 8;
            if (i + 2 < bytes.size())
                v |= static_cast<uint8_t>(bytes[i + 2]);
            out += alphabet[(v >> 18) & 63];
            out += alphabet[(v >> 12) & 63];
            out += i + 1 < bytes.size() ? alphabet[(v >> 6) & 63] : '=';
            out += i + 2 < bytes.size() ? alphabet[v & 63] : '=';
        }
        return out;
    }

    inline std::string hexBytes(const uint8_t *bytes, size_t size)
    {
        std::string result;
        result.reserve(size * 2);
        for (size_t i = 0; i < size; ++i)
        {
            result += "0123456789abcdef"[bytes[i] >> 4];
            result += "0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }

    inline std::string readBounded(const std::filesystem::path &path, size_t limit)
    {
        std::error_code ignored;
        if (!std::filesystem::is_regular_file(path, ignored) ||
            std::filesystem::is_symlink(path, ignored))
            throw std::runtime_error("Release manifest input is missing");
        const auto size = std::filesystem::file_size(path);
        if (!size || size > limit)
            throw std::runtime_error("Release manifest input exceeds its bounds");
        std::ifstream file(path, std::ios::binary);
        std::string data(static_cast<size_t>(size), '\0');
        file.read(data.data(), static_cast<std::streamsize>(size));
        if (static_cast<size_t>(file.gcount()) != size)
            throw std::runtime_error("Release manifest input is unreadable");
        return data;
    }

    // A manifest blob is embedded only if it still hashes to what the catalog promises.
    inline std::string verifiedBlob(const std::filesystem::path &path,
                                    const std::string &digest,
                                    uint64_t size)
    {
        if (!digestName(digest) || !size || size > RELEASE_MANIFEST_BLOB_LIMIT)
            throw std::runtime_error("Invalid release manifest blob identity");
        auto blob = readBounded(path, RELEASE_MANIFEST_BLOB_LIMIT);
        const auto actual = crypto::sha256(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(blob.data()), blob.size()));
        if (blob.size() != size || hexBytes(actual.data(), actual.size()) != digest)
            throw std::runtime_error("Published release manifest blob does not verify");
        return blob;
    }

    inline std::string releaseManifest(const std::filesystem::path &root,
                                       const std::string &nonceHex,
                                       uint64_t now)
    {
        using Json = nlohmann::json;
        if (!digestName(nonceHex)) // exactly 64 lowercase hex characters
            throw std::invalid_argument("Invalid release manifest nonce");
        const auto updates = root / "updates";
        const auto catalog = Json::parse(
            readBounded(updates / "full-image-catalog.json", RELEASE_CATALOG_LIMIT));
        if (catalog.at("schema") != 1 || catalog.at("format") != "full-executable-v1")
            throw std::runtime_error("Unsupported executable catalog");
        const auto latest = catalog.at("latest").get<std::string>();
        const auto size = catalog.at("target_size").get<uint64_t>();
        const auto release = catalog.at("release").get<uint64_t>();
        if (!digestName(latest) || !size || size > DW_UPDATE_MAX_IMAGE || !release ||
            std::filesystem::file_size(updates / "images" / (latest + ".exe")) != size)
            throw std::runtime_error("Full executable is not completely published");

        Json document = {{"schema", 1},
                         {"nonce", nonceHex},
                         {"issued", now},
                         {"expires", now + RELEASE_DOCUMENT_LIFETIME},
                         {"executable", {{"release", release}, {"sha256", latest}, {"size", size}}},
                         {"maps", nullptr},
                         {"overlays", nullptr}};
        if (catalog.contains("maps"))
        {
            const auto &maps = catalog.at("maps");
            const auto digest = maps.at("manifest_sha256").get<std::string>();
            const auto manifestSize = maps.at("manifest_size").get<uint64_t>();
            const auto blob =
                verifiedBlob(updates / "map-manifests" / (digest + ".bin"), digest, manifestSize);
            document["maps"] = {{"package_hash", maps.at("package_hash")},
                                {"manifest_sha256", digest},
                                {"manifest_size", manifestSize},
                                {"files", maps.at("files")},
                                {"chunks", maps.at("chunks")},
                                {"manifest_b64", base64(blob)}};
        }
        if (catalog.contains("assets"))
        {
            const auto &assets = catalog.at("assets");
            const auto digest = assets.at("manifest_sha256").get<std::string>();
            const auto manifestSize = assets.at("manifest_size").get<uint64_t>();
            // The publisher stores this manifest under the executable that embeds it.
            const auto blob = verifiedBlob(updates / "asset-manifests" / (latest + ".bin"),
                                           digest,
                                           manifestSize);
            document["overlays"] = {{"manifest_sha256", digest},
                                    {"manifest_size", manifestSize},
                                    {"files", assets.at("files")},
                                    {"payloads", assets.at("payloads")},
                                    {"manifest_b64", base64(blob)}};
        }
        // nlohmann orders object keys, so these bytes are stable for a given input.
        auto text = document.dump();
        if (text.size() > RELEASE_DOCUMENT_LIMIT)
            throw std::runtime_error("Release manifest exceeds its bounds");
        return text;
    }
} // namespace executable_updates
