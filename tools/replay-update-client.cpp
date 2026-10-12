// Embedded in the freshly compiled game. Runs outside the game process so the
// running image is never edited and Windows can replace it after a clean exit.
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include "../integration/replay/dw_update_protocol.h"
#if __has_include("../integration/replay/DW_UpdateAssetManifest.h")
#include "../integration/replay/DW_UpdateAssetManifest.h"
#define DW_UPDATE_FROZEN_ASSETS 1
#endif
#include "replay-update-assets.h"

extern "C" bool DW_LocalPlatform_VerifyBytes(const void *, unsigned, const uint8_t *);
extern "C" uint64_t DW_LocalPlatform_Time();

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
        std::ifstream file(path, std::ios::binary | std::ios::ate);
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
        Handle file(CreateFileW(path.c_str(),
                                GENERIC_WRITE,
                                0,
                                nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                                nullptr));
        require(file.value != INVALID_HANDLE_VALUE,
                "Cannot stage update; check free space and folder permissions");
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
        require(FlushFileBuffers(file.value) != 0, "Cannot flush staged update");
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
        Http connection(WinHttpConnect(session.value, host.c_str(), 8085, 0));
        Http request(WinHttpOpenRequest(connection.value,
                                        body.empty() ? L"GET" : L"POST",
                                        path.c_str(),
                                        nullptr,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        0));
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

    const update_assets::IO assetIO{read, write, hash, download};

    bool validPlan(const DWUpdateReply &reply)
    {
        const auto &p = reply.plan;
        const auto now = DW_LocalPlatform_Time();
        return p.magic == DW_UPDATE_MAGIC && p.version == 2 && p.status <= 2 &&
               p.issued <= now + 30 && p.expires > now && p.expires > p.issued &&
               p.expires - p.issued <= 86400 &&
               DW_LocalPlatform_VerifyBytes(&p, sizeof(p), reply.signature);
    }

    fs::path stage(const fs::path &exe)
    {
        return exe.parent_path() / (exe.filename().wstring() + L".update");
    }

    int prepare(const fs::path &exe, const std::wstring &host)
    {
        const auto base = read(exe);
        DWUpdateRequest request{};
        request.magic = DW_UPDATE_MAGIC;
        request.version = 2;
        require(BCryptGenRandom(nullptr,
                                request.nonce,
                                sizeof(request.nonce),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
                "Cannot create update nonce");
        const auto baseHash = hash(base);
        std::copy(baseHash.begin(), baseHash.end(), request.baseHash);
        const auto response =
            download(host,
                     L"/updates/v2/check",
                     {reinterpret_cast<const uint8_t *>(&request), sizeof(request)},
                     sizeof(DWUpdateReply));
        DWUpdateReply reply{};
        std::memcpy(&reply, response.data(), sizeof(reply));
        require(validPlan(reply) && !std::memcmp(reply.plan.nonce, request.nonce, 32) &&
                    !std::memcmp(reply.plan.baseHash, request.baseHash, 32),
                "Untrusted, stale or mismatched update manifest");
        const auto &p = reply.plan;
        if (p.status == 2)
            return 30;
        if (p.status == 0)
        {
            require(!std::memcmp(p.targetHash, p.baseHash, 32) && p.targetSize == base.size(),
                    "Invalid current-build response");
            update_assets::Session assets(assetIO, exe, stage(exe), base, p.targetHash);
            if (!assets.needed())
                return 10;
            assets.stage(host);
            write(stage(exe) / "plan.bin", response);
            return 20; // Missing owned files require the same clean-exit fence.
        }
        require(!p.baseSize && p.targetSize && p.targetSize <= DW_UPDATE_MAX_IMAGE &&
                    p.patchSize == p.targetSize && p.release &&
                    !std::memcmp(p.patchHash, p.targetHash, 32) &&
                    std::memcmp(p.baseHash, p.targetHash, 32),
                "Invalid executable update bounds");
        const auto target =
            download(host, L"/updates/v2/image/" + hex(p.targetHash), {}, p.targetSize);
        require(target.size() > 2 && target[0] == 'M' && target[1] == 'Z' &&
                    matches(target, p.targetHash),
                "Downloaded executable failed verification");
        update_assets::Session assets(assetIO, exe, stage(exe), target, p.targetHash);
        assets.stage(host);
        write(stage(exe) / "next.exe", target);
        write(stage(exe) / "plan.bin", response);
        return 20;
    }

    void apply(const fs::path &exe, DWORD parent, const std::wstring &eventName)
    {
        Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent));
        require(process.value != nullptr, "Cannot bind the running game process");
        std::wstring running(32768, L'\0');
        DWORD size = static_cast<DWORD>(running.size());
        require(QueryFullProcessImageNameW(process.value, 0, running.data(), &size) != 0,
                "Cannot identify the running game");
        running.resize(size);
        require(fs::equivalent(running, exe), "Updater parent is not the selected game");
        const auto bytes = read(stage(exe) / "plan.bin", sizeof(DWUpdateReply));
        require(bytes.size() == sizeof(DWUpdateReply), "Staged update manifest is incomplete");
        DWUpdateReply reply{};
        std::memcpy(&reply, bytes.data(), sizeof(reply));
        const auto next = stage(exe) / "next.exe";
        require(validPlan(reply) && reply.plan.status <= 1 &&
                    matches(read(exe), reply.plan.baseHash) &&
                    (reply.plan.status == 1 ? matches(read(next), reply.plan.targetHash)
                                           : !std::memcmp(reply.plan.targetHash, reply.plan.baseHash, 32)),
                "Staged update no longer verifies");
        const auto target = read(reply.plan.status == 1 ? next : exe);
        update_assets::Session assets(assetIO, exe, stage(exe), target, reply.plan.targetHash);
        assets.verifyStage();
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName.c_str()));
        require(ready.value && SetEvent(ready.value), "Cannot acknowledge the restart handoff");
        require(WaitForSingleObject(process.value, 86400000) == WAIT_OBJECT_0,
                "Game did not exit before update expiry");
        require(validPlan(reply) && matches(read(exe), reply.plan.baseHash) &&
                    (reply.plan.status == 0 || matches(read(next), reply.plan.targetHash)),
                "Executable changed while waiting for the game to exit");
        assets.install(); // All original overlay bytes backed up before replacement.
        if (reply.plan.status == 1)
        {
            const auto backup = stage(exe) / (hex(reply.plan.baseHash) + L".backup.exe");
            // ReplaceFile preserves file ACLs and the old bytes as a recovery copy.
            // It is never followed by delete/move fallbacks that could lose the EXE.
            bool replaced = false;
            for (unsigned attempt = 0; attempt < 50; ++attempt)
            {
                if (ReplaceFileW(exe.c_str(), next.c_str(), backup.c_str(), 0, nullptr, nullptr))
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
                    require(CopyFileW(backup.c_str(), rollback.c_str(), FALSE) != 0 &&
                                MoveFileExW(rollback.c_str(), exe.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
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
                require(CopyFileW(backup.c_str(), rollback.c_str(), FALSE) != 0 &&
                            ReplaceFileW(exe.c_str(), rollback.c_str(), nullptr, 0, nullptr, nullptr) !=
                                0,
                        "Final verification failed; restore the retained backup EXE");
                throw std::runtime_error(
                    "Final verification failed; restored the previous EXE without launching it");
            }
        }
        assets.commit();
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
        fs::create_directories(folder);
        Handle lock(CreateFileW((folder / "operation.lock").c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr));
        require(lock.value != INVALID_HANDLE_VALUE,
                "Another updater is already using this game installation");
        if (std::wstring(argv[1]) == L"--prepare" && argc == 4)
        {
            const int result = prepare(exe, argv[3]);
            std::ofstream(folder / "result.log", std::ios::app)
                << "prepare result=" << result << '\n';
            return result;
        }
        require(std::wstring(argv[1]) == L"--apply" && argc == 5, "Invalid updater mode");
        apply(exe, std::stoul(argv[3]), argv[4]);
        std::ofstream(folder / "result.log", std::ios::app)
            << "verified replacement and relaunch completed\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        if (!exe.empty())
            std::ofstream(stage(exe) / "result.log", std::ios::app) << error.what() << '\n';
        return 40;
    }
}
