// Embedded in the freshly compiled game. Runs outside the game process so the
// running image is never edited and Windows can replace it after a clean exit.
#include <windows.h>
#include <bcrypt.h>
#include <compressapi.h>
#include <winhttp.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include "../integration/replay/dw_update_protocol.h"
#include "../integration/replay/dw_local_trust.h"
#if __has_include("../integration/replay/DW_UpdateAssetManifest.h")
#include "../integration/replay/DW_UpdateAssetManifest.h"
#define DW_UPDATE_FROZEN_ASSETS 1
#endif
#if __has_include("../integration/replay/DW_UpdateMapManifest.h")
#include "../integration/replay/DW_UpdateMapManifest.h"
#define DW_UPDATE_FROZEN_MAPS 1
#endif
#include "replay-update-assets.h"

namespace
{
    namespace fs = std::filesystem;
    using Bytes = std::vector<uint8_t>;

    struct Handle
    {
        HANDLE value = INVALID_HANDLE_VALUE;

        explicit Handle(HANDLE item) : value(item) {}

        ~Handle()
        {
            if (value && value != INVALID_HANDLE_VALUE)
                CloseHandle(value);
        }

        Handle(const Handle &) = delete;
        Handle &operator=(const Handle &) = delete;
    };

    struct Http
    {
        HINTERNET value;

        explicit Http(HINTERNET item) : value(item)
        {
            if (!value)
                throw std::runtime_error("Cannot open update transport");
        }

        ~Http()
        {
            WinHttpCloseHandle(value);
        }

        Http(const Http &) = delete;
        Http &operator=(const Http &) = delete;
    };

    void require(bool condition, const char *message)
    {
        if (!condition)
            throw std::runtime_error(message);
    }

    Bytes read(const fs::path &path, uint64_t limit = DW_UPDATE_MAX_IMAGE)
    {
        std::ifstream file(update_assets::nativePath(path), std::ios::binary | std::ios::ate);
        require(file.good(), "Cannot read update input");
        const auto length = file.tellg();
        require(length >= 0 && static_cast<uint64_t>(length) <= limit,
                "Update input exceeds bounds");
        Bytes bytes(static_cast<size_t>(length));
        file.seekg(0);
        file.read(reinterpret_cast<char *>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        require(file.good(), "Incomplete update input");
        return bytes;
    }

    std::array<uint8_t, 32> hash(std::span<const uint8_t> bytes)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE digest = nullptr;
        require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
                "SHA256 unavailable");
        std::array<uint8_t, 32> result{};
        bool ok =
            BCryptCreateHash(algorithm, &digest, nullptr, 0, nullptr, 0, 0) >= 0 &&
            BCryptHashData(
                digest, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) >=
                0 &&
            BCryptFinishHash(digest, result.data(), static_cast<ULONG>(result.size()), 0) >= 0;
        if (digest)
            BCryptDestroyHash(digest);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        require(ok, "SHA256 failed");
        return result;
    }

    bool matches(std::span<const uint8_t> bytes, const uint8_t *expected)
    {
        const auto actual = hash(bytes);
        return std::equal(actual.begin(), actual.end(), expected);
    }

    std::wstring hex(const uint8_t *bytes)
    {
        std::wstring result;
        for (unsigned i = 0; i < 32; ++i)
        {
            result += L"0123456789abcdef"[bytes[i] >> 4];
            result += L"0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }

    void write(const fs::path &path, std::span<const uint8_t> bytes)
    {
        const auto native = update_assets::nativePath(path);
        Handle file(CreateFileW(native.c_str(),
                                GENERIC_WRITE,
                                0,
                                nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                                nullptr));
        update_assets::requireWin32(file.value != INVALID_HANDLE_VALUE, "Cannot stage update");
        size_t at = 0;
        while (at < bytes.size())
        {
            DWORD count = 0;
            const auto wanted =
                static_cast<DWORD>(std::min<size_t>(1024 * 1024, bytes.size() - at));
            require(WriteFile(file.value, bytes.data() + at, wanted, &count, nullptr) &&
                        count == wanted,
                    "Update write failed; the installed EXE is unchanged");
            at += count;
        }
        update_assets::requireWin32(FlushFileBuffers(file.value) != 0, "Cannot flush staged update");
    }

    Bytes download(const std::wstring &host,
                   const std::wstring &path,
                   std::span<const uint8_t> body,
                   uint64_t size)
    {
        require(size <= DW_UPDATE_MAX_IMAGE, "Update download exceeds bounds");
        Http session(WinHttpOpen(L"Replay-EXE-Updater/1",
                                 WINHTTP_ACCESS_TYPE_NO_PROXY,
                                 WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS,
                                 0));
        require(WinHttpSetTimeouts(session.value, 10000, 10000, 10000, 30000) != 0,
                "Cannot set update timeouts");
        const bool tls = host != L"127.0.0.1";
        Http connection(WinHttpConnect(session.value, host.c_str(), tls ? 8443 : 8085, 0));
        Http request(WinHttpOpenRequest(connection.value,
                                        body.empty() ? L"GET" : L"POST",
                                        path.c_str(),
                                        nullptr,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        tls ? WINHTTP_FLAG_SECURE : 0));
        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        require(WinHttpSetOption(
                    request.value, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)) != 0,
                "Cannot disable update redirects");
        require(WinHttpSendRequest(request.value,
                                   WINHTTP_NO_ADDITIONAL_HEADERS,
                                   0,
                                   body.empty() ? WINHTTP_NO_REQUEST_DATA
                                                : const_cast<uint8_t *>(body.data()),
                                   static_cast<DWORD>(body.size()),
                                   static_cast<DWORD>(body.size()),
                                   0) &&
                    WinHttpReceiveResponse(request.value, nullptr),
                "Update server unavailable");
        DWORD status = 0, length = sizeof(status);
        require(WinHttpQueryHeaders(request.value,
                                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    nullptr,
                                    &status,
                                    &length,
                                    nullptr) &&
                    status == 200,
                "Update server rejected the request");
        DWORD contentSize = 0;
        length = sizeof(contentSize);
        require(WinHttpQueryHeaders(request.value,
                                    WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                                    nullptr,
                                    &contentSize,
                                    &length,
                                    nullptr) &&
                    contentSize == size,
                "Unexpected update response size");
        Bytes result(static_cast<size_t>(size));
        size_t at = 0;
        const auto deadline = GetTickCount64() + 10 * 60 * 1000;
        while (at < result.size())
        {
            DWORD count = 0;
            require(GetTickCount64() < deadline &&
                        WinHttpReadData(
                            request.value,
                            result.data() + at,
                            static_cast<DWORD>(std::min<size_t>(1024 * 1024, result.size() - at)),
                            &count) &&
                        count,
                    "Update download interrupted; retry at the next launch");
            at += count;
        }
        uint8_t extra = 0;
        DWORD count = 0;
        require(WinHttpReadData(request.value, &extra, 1, &count) && !count,
                "Unexpected bytes after update");
        return result;
    }

    Bytes decompressMap(std::span<const uint8_t> compressed, uint32_t size)
    {
        require(size && size <= DW_UPDATE_MAP_CHUNK_BYTES &&
                    compressed.size() <= DW_UPDATE_MAP_MAX_TRANSPORT_BYTES, "Map decompression bounds failed");
        DECOMPRESSOR_HANDLE decoder{};
        require(CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &decoder) != 0,
                "Native Windows map decompressor unavailable");
        Bytes raw(size);
        SIZE_T actual = 0;
        const bool valid = Decompress(decoder, const_cast<uint8_t *>(compressed.data()), compressed.size(),
                                      raw.data(), raw.size(), &actual) != 0 && actual == size;
        CloseDecompressor(decoder);
        require(valid, "Compressed map payload is invalid");
        return raw;
    }

    const update_assets::IO assetIO{read, write, hash, download, decompressMap};

    bool verifyPlanSignature(const DWUpdateReply &reply)
    {
        // The updater needs only the pinned public key and Windows CNG. Do not
        // link game account/license emulation or dynamically resolve crypto APIs.
        const auto digest = hash({reinterpret_cast<const uint8_t *>(&reply.plan),
                                  sizeof(reply.plan)});
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0) < 0)
            return false;
        BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, 32};
        const bool valid =
            BCryptImportKeyPair(algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
                                const_cast<PUCHAR>(s_dwLocalPlatformPublicKey),
                                sizeof(s_dwLocalPlatformPublicKey), 0) >= 0 &&
            BCryptVerifySignature(key, &padding, const_cast<PUCHAR>(digest.data()),
                                  static_cast<ULONG>(digest.size()),
                                  const_cast<PUCHAR>(reply.signature), sizeof(reply.signature),
                                  BCRYPT_PAD_PSS) >= 0;
        if (key)
            BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return valid;
    }

    bool validPlan(const DWUpdateReply &reply)
    {
        const auto &p = reply.plan;
        FILETIME time{};
        GetSystemTimeAsFileTime(&time);
        const uint64_t ticks = (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
        const auto now = ticks / 10000000ULL - 11644473600ULL;
        return p.magic == DW_UPDATE_MAGIC && p.version == 2 && p.status <= 2 &&
               p.issued <= now + 30 && p.expires > now && p.expires > p.issued &&
               p.expires - p.issued <= 86400 &&
               verifyPlanSignature(reply);
    }

    fs::path stage(const fs::path &exe)
    {
        return exe.parent_path() / (exe.filename().wstring() + L".update");
    }

    DWUpdateReply freshPlan(std::span<const uint8_t> base, const std::wstring &host)
    {
        DWUpdateRequest request{};
        request.magic = DW_UPDATE_MAGIC; request.version = 2;
        require(BCryptGenRandom(nullptr, request.nonce, sizeof(request.nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
                "Cannot create update nonce");
        const auto identity = hash(base);
        std::copy(identity.begin(), identity.end(), request.baseHash);
        const auto response = download(host, L"/updates/v2/check",
            {reinterpret_cast<const uint8_t *>(&request), sizeof(request)}, sizeof(DWUpdateReply));
        DWUpdateReply reply{};
        std::memcpy(&reply, response.data(), sizeof(reply));
        require(validPlan(reply) && !std::memcmp(reply.plan.nonce, request.nonce, 32) &&
                    !std::memcmp(reply.plan.baseHash, request.baseHash, 32),
                "Untrusted, stale or mismatched update manifest");
        const auto &p = reply.plan;
        if (p.status == 0)
            require(!std::memcmp(p.targetHash, p.baseHash, 32) && p.targetSize == base.size(),
                    "Invalid current-build response");
        else if (p.status == 1)
            require(!p.baseSize && p.targetSize && p.targetSize <= DW_UPDATE_MAX_IMAGE &&
                        p.patchSize == p.targetSize && p.release && !std::memcmp(p.patchHash, p.targetHash, 32) &&
                        std::memcmp(p.baseHash, p.targetHash, 32), "Invalid executable update bounds");
        return reply;
    }

    void frozenAssetsMatch(std::span<const uint8_t> target)
    {
#if defined(DW_UPDATE_FROZEN_ASSETS)
        const auto own = update_assets::manifest(assetIO, s_dwUpdateAssetManifest);
        const auto latest = update_assets::manifest(assetIO, target);
        require(own.size() == latest.size() && !own.empty() &&
                    !std::memcmp(own.data(), latest.data(), own.size() * sizeof(DWUpdateAssetEntry)),
                "Asset-only helper is not bound to the latest owned overlay manifest");
#else
        require(update_assets::manifest(assetIO, target).empty(), "Asset-only helper has no frozen overlay manifest");
#endif
#if defined(DW_UPDATE_FROZEN_MAPS)
        const auto ownMaps = update_assets::mapManifest(assetIO, s_dwUpdateMapManifest);
        const auto latestMaps = update_assets::mapManifest(assetIO, target);
        require(ownMaps.files.size() == latestMaps.files.size() && ownMaps.chunks.size() == latestMaps.chunks.size() &&
                    !std::memcmp(ownMaps.files.data(), latestMaps.files.data(), ownMaps.files.size() * sizeof(DWUpdateMapFile)) &&
                    !std::memcmp(ownMaps.chunks.data(), latestMaps.chunks.data(), ownMaps.chunks.size() * sizeof(DWUpdateMapChunk)),
                "Asset-only helper is not bound to the latest map manifest");
#else
        require(update_assets::mapManifest(assetIO, target).files.empty(), "Asset-only helper has no frozen map manifest");
#endif
    }

    struct UpdateContext
    {
        uint64_t magic = 0x3158544357445552ULL;
        uint32_t assetsOnly = 0, reserved = 0;
        uint8_t targetHash[32]{};
        wchar_t host[256]{};
    };
    void savePlan(const fs::path &exe, const std::wstring &host, bool assetsOnly, const DWUpdateReply &reply)
    {
        require(!host.empty() && host.size() < 256 && host.find(L'\0') == std::wstring::npos,
                "Invalid updater host");
        UpdateContext context;
        context.assetsOnly = assetsOnly ? 1 : 0;
        std::copy(std::begin(reply.plan.targetHash), std::end(reply.plan.targetHash), context.targetHash);
        std::copy(host.begin(), host.end(), context.host);
        update_assets::safePath(stage(exe) / "context.bin"); update_assets::safePath(stage(exe) / "plan.bin");
        write(stage(exe) / "context.bin", {reinterpret_cast<const uint8_t *>(&context), sizeof(context)});
        write(stage(exe) / "plan.bin", {reinterpret_cast<const uint8_t *>(&reply), sizeof(reply)});
    }
    UpdateContext loadContext(const fs::path &exe, bool assetsOnly, const DWUpdateReply &reply)
    {
        update_assets::safePath(stage(exe) / "context.bin");
        const auto bytes = read(stage(exe) / "context.bin", sizeof(UpdateContext));
        require(bytes.size() == sizeof(UpdateContext), "Missing update mode and host context");
        UpdateContext context{};
        std::memcpy(&context, bytes.data(), sizeof(context));
        const auto end = std::find(std::begin(context.host), std::end(context.host), L'\0');
        require(context.magic == UpdateContext{}.magic && !context.reserved && context.assetsOnly == unsigned(assetsOnly) &&
                    end != std::begin(context.host) && end != std::end(context.host) &&
                    std::all_of(end, std::end(context.host), [](wchar_t c) { return c == 0; }) &&
                    !std::memcmp(context.targetHash, reply.plan.targetHash, 32), "Staged updater mode or target changed");
        return context;
    }
    void unchangedTarget(const DWUpdateReply &fresh, const DWUpdateReply &original)
    {
        require(fresh.plan.status <= 1 && fresh.plan.status == original.plan.status &&
                    !std::memcmp(fresh.plan.targetHash, original.plan.targetHash, 32) &&
                    fresh.plan.targetSize == original.plan.targetSize && fresh.plan.release == original.plan.release,
                "Latest signed target changed while downloading; retry the update");
    }

    int prepare(const fs::path &exe, const std::wstring &host, bool assetsOnly)
    {
        const auto base = read(exe);
        auto reply = freshPlan(base, host);
        if (reply.plan.status == 2)
            return 30;
        const auto &p = reply.plan;
        Bytes target;
        if (p.status == 0)
            target = base;
        else
        {
            const auto cache = stage(exe) / (assetsOnly ? "verified-target.exe" : "next.exe");
            update_assets::safePath(cache);
            if (fs::is_regular_file(cache) && fs::file_size(cache) == p.targetSize)
                target = read(cache);
            if (target.size() != p.targetSize || !matches(target, p.targetHash))
                target = download(host, L"/updates/v2/image/" + hex(p.targetHash), {}, p.targetSize);
            require(target.size() > 2 && target[0] == 'M' && target[1] == 'Z' && matches(target, p.targetHash),
                    "Downloaded executable failed verification");
            // This file is evidence of the signed target in asset-only mode; it is never installed.
        }
        if (!assetsOnly && p.status == 1)
        {
            // Executable first: an outdated client stages only the signed latest
            // EXE. That EXE stages its owned assets and map data itself once it is
            // the one running (its first check reports status 0).
            update_assets::manifest(assetIO, target);
            update_assets::mapManifest(assetIO, target); // reject a malformed target now
            write(stage(exe) / "next.exe", target);
            require(matches(read(exe), reply.plan.baseHash), "Installed executable changed during staging");
            savePlan(exe, host, false, reply);
            return 20;
        }
        if (assetsOnly && p.status == 1)
            frozenAssetsMatch(target);
        update_assets::Session assets(assetIO, exe, stage(exe), target, p.targetHash);
        if ((assetsOnly || p.status == 0) && !assets.needed())
        {
            assets.discardStaging();
            return 10;
        }
        assets.stage(host);
        if (p.status == 1)
            write(stage(exe) / (assetsOnly ? "verified-target.exe" : "next.exe"), target);
        // A large map transfer can outlast its original signed plan. Refresh with a
        // new nonce and require the exact same target before making it actionable.
        if (!update_assets::mapManifest(assetIO, target).files.empty())
        {
            const auto refreshed = freshPlan(base, host);
            unchangedTarget(refreshed, reply); reply = refreshed;
        }
        require(matches(read(exe), reply.plan.baseHash), "Installed executable changed during staging");
        savePlan(exe, host, assetsOnly, reply);
        return 20;
    }

    void apply(const fs::path &exe, DWORD parent, const std::wstring &eventName, bool assetsOnly)
    {
        Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent));
        require(process.value != nullptr, "Cannot bind the running game process");
        std::wstring running(32768, L'\0');
        DWORD size = static_cast<DWORD>(running.size());
        require(QueryFullProcessImageNameW(process.value, 0, running.data(), &size) != 0,
                "Cannot identify the running game");
        running.resize(size);
        require(fs::equivalent(running, exe), "Updater parent is not the selected game");
        update_assets::safePath(stage(exe) / "plan.bin");
        const auto bytes = read(stage(exe) / "plan.bin", sizeof(DWUpdateReply));
        require(bytes.size() == sizeof(DWUpdateReply), "Staged update manifest is incomplete");
        DWUpdateReply reply{};
        std::memcpy(&reply, bytes.data(), sizeof(reply));
        const auto context = loadContext(exe, assetsOnly, reply);
        require(verifyPlanSignature(reply) && reply.plan.magic == DW_UPDATE_MAGIC && reply.plan.version == 2 &&
                    reply.plan.status <= 1 && matches(read(exe), reply.plan.baseHash),
                "Staged update no longer verifies");
        const auto next = stage(exe) / (assetsOnly ? "verified-target.exe" : "next.exe");
        update_assets::safePath(next);
        const auto target = read(reply.plan.status == 1 ? next : exe);
        require(target.size() == reply.plan.targetSize && matches(target, reply.plan.targetHash),
                "Staged target executable failed verification");
        if (assetsOnly && reply.plan.status == 1)
            frozenAssetsMatch(target);
        const auto refreshed = freshPlan(read(exe), context.host);
        unchangedTarget(refreshed, reply); reply = refreshed;
        // An executable update installs only the EXE (see prepare); asset and
        // map changes are applied by a later update from the latest EXE.
        const bool executableOnly = !assetsOnly && reply.plan.status == 1;
        std::optional<update_assets::Session> assets;
        if (!executableOnly)
        {
            assets.emplace(assetIO, exe, stage(exe), target, reply.plan.targetHash);
            assets->verifyStage();
        }
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName.c_str()));
        require(ready.value && SetEvent(ready.value), "Cannot acknowledge the restart handoff");
        require(WaitForSingleObject(process.value, 86400000) == WAIT_OBJECT_0,
                "Game did not exit before update expiry");
        require(matches(read(exe), reply.plan.baseHash) && matches(target, reply.plan.targetHash),
                "Executable changed while waiting for the game to exit");
        const auto afterExit = freshPlan(read(exe), context.host);
        unchangedTarget(afterExit, reply); reply = afterExit;
        require(validPlan(reply), "Update plan expired before installation");
        update_assets::safePath(exe); update_assets::safePath(next);
        require(reply.plan.status == 0 || matches(read(next), reply.plan.targetHash),
                "Staged target changed while waiting for the game to exit");
        if (assets)
            assets->install(); // All original overlay bytes backed up before replacement.
        if (!assetsOnly && reply.plan.status == 1)
        {
            const auto backup = stage(exe) / (hex(reply.plan.baseHash) + L".backup.exe");
            update_assets::safePath(backup);
            // ReplaceFile preserves file ACLs and the old bytes as a recovery copy.
            // It is never followed by delete/move fallbacks that could lose the EXE.
            bool replaced = false;
            for (unsigned attempt = 0; attempt < 50; ++attempt)
            {
                if (ReplaceFileW(update_assets::nativePath(exe).c_str(), update_assets::nativePath(next).c_str(), update_assets::nativePath(backup).c_str(), 0, nullptr, nullptr))
                {
                    replaced = true;
                    break;
                }
                const auto error = GetLastError();
                if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED)
                    break;
                Sleep(100);
            }
            if (!replaced)
            {
                // ReplaceFile documents failures that can leave the original under
                // the backup name. Restore a missing launch path without replacing
                // any existing file or consuming the recovery copy.
                if (!fs::exists(exe) && fs::exists(backup) &&
                    matches(read(backup), reply.plan.baseHash))
                {
                    const auto rollback = stage(exe) / "rollback.exe";
                    require(CopyFileW(update_assets::nativePath(backup).c_str(), update_assets::nativePath(rollback).c_str(), FALSE) != 0 &&
                                MoveFileExW(update_assets::nativePath(rollback).c_str(), update_assets::nativePath(exe).c_str(), MOVEFILE_WRITE_THROUGH) != 0,
                            "Replacement failed; restore the retained backup EXE to the game folder");
                }
                throw std::runtime_error("Windows could not replace the EXE; installed image and "
                                         "recovery files are retained");
            }
            if (!matches(read(exe), reply.plan.targetHash))
            {
                require(matches(read(backup), reply.plan.baseHash),
                        "Installed image and recovery backup failed verification");
                const auto rollback = stage(exe) / "rollback.exe";
                require(CopyFileW(update_assets::nativePath(backup).c_str(), update_assets::nativePath(rollback).c_str(), FALSE) != 0 &&
                            ReplaceFileW(update_assets::nativePath(exe).c_str(), update_assets::nativePath(rollback).c_str(), nullptr, 0, nullptr, nullptr) !=
                                0,
                        "Final verification failed; restore the retained backup EXE");
                throw std::runtime_error(
                    "Final verification failed; restored the previous EXE without launching it");
            }
        }
        if (assets)
            assets->commit();
        if (assetsOnly && reply.plan.status == 1)
            DeleteFileW(update_assets::nativePath(next).c_str()); // downloaded evidence copy only
        std::wstring command = L"\"" + exe.wstring() + L"\"";
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION child{};
        require(CreateProcessW(exe.c_str(),
                               command.data(),
                               nullptr,
                               nullptr,
                               FALSE,
                               0,
                               nullptr,
                               exe.parent_path().c_str(),
                               &startup,
                               &child) != 0,
                "Update installed successfully; launch the game again manually");
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
    }
} // namespace

int wmain(int argc, wchar_t **argv)
{
    fs::path exe;
    try
    {
        // Frozen game helpers retain their manifest. A standalone backend-tool
        // build can still consume manifests from verified downloaded game EXEs.
#if defined(DW_UPDATE_FROZEN_ASSETS)
        require(!update_assets::manifest(assetIO, s_dwUpdateAssetManifest).empty(),
                "Compiled owned asset manifest is unavailable");
#endif
        require(argc >= 4, "Invalid updater arguments");
        exe = fs::absolute(argv[2]).lexically_normal();
        require(exe.extension() == L".exe" && fs::is_regular_file(exe),
                "Executable is unavailable");
        const auto folder = stage(exe);
        update_assets::safePath(exe.parent_path()); update_assets::safePath(exe);
        update_assets::directory(folder);
        update_assets::safePath(folder / "operation.lock");
        const auto lockPath = update_assets::nativePath(folder / "operation.lock");
        Handle lock(CreateFileW(lockPath.c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr));
        require(lock.value != INVALID_HANDLE_VALUE,
                "Another updater is already using this game installation");
        const std::wstring mode = argv[1];
        if ((mode == L"--prepare" || mode == L"--prepare-assets") && argc == 4)
        {
            const int result = prepare(exe, argv[3], mode == L"--prepare-assets");
            std::ofstream(update_assets::nativePath(folder / "result.log"), std::ios::app)
                << "prepare result=" << result << '\n';
            return result;
        }
        require((mode == L"--apply" || mode == L"--apply-assets") && argc == 5, "Invalid updater mode");
        apply(exe, std::stoul(argv[3]), argv[4], mode == L"--apply-assets");
        std::ofstream(update_assets::nativePath(folder / "result.log"), std::ios::app)
            << "verified replacement and relaunch completed\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        if (!exe.empty())
            std::ofstream(update_assets::nativePath(stage(exe) / "result.log"), std::ios::app) << error.what() << '\n';
        return 40;
    }
}
