// Standalone local diagnostic. Existing identity only; no login or account reset.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <array>
#include <cstdio>
#include <cstdint>
#include <string>
#include "../integration/replay/dw_client_identity.h"

namespace
{
    struct ExistingRecord
    {
        HANDLE handle;

        ~ExistingRecord()
        {
            CloseHandle(handle);
        }
    };
} // namespace

int wmain()
{
    std::puts("Replay DW identity diagnostic: no server requests; no identity deletion.");
    wchar_t directory[1024]{};
    const auto length = GetEnvironmentVariableW(L"LOCALAPPDATA", directory, 1024);
    if (!length || length >= 1024)
    {
        std::printf("LOCALAPPDATA failed: Win32=%lu\n", GetLastError());
        return 1;
    }
    const std::wstring path = std::wstring(directory) + L"\\ReplayDW\\player-identity.bin";
    const auto file = CreateFileW(path.c_str(),
                                  GENERIC_READ,
                                  FILE_SHARE_READ,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        std::printf("Existing identity open failed: Win32=%lu\n", GetLastError());
        return 1; // Never call the creation path if no identity exists.
    }
    // Keep the existing record open without write/delete sharing throughout
    // the native loader check. It cannot disappear and trigger first creation,
    // nor can another process replace it between the two reads.
    ExistingRecord existing{file};
    LARGE_INTEGER size{};
    std::array<uint8_t, 4108> bytes{};
    DWORD count = 0;
    const bool read =
        GetFileSizeEx(file, &size) && size.QuadPart >= 13 &&
        size.QuadPart <= static_cast<LONGLONG>(bytes.size()) &&
        ReadFile(file, bytes.data(), static_cast<DWORD>(size.QuadPart), &count, nullptr);
    const auto readError = GetLastError();
    if (!read || count != size.QuadPart)
    {
        std::printf("Identity read failed: bytes=%lld Win32=%lu\n", size.QuadPart, readError);
        return 1;
    }
    const auto *header = reinterpret_cast<const uint32_t *>(bytes.data());
    std::printf("Identity size=%lu, magic=%08X, version=%u, payload=%u\n",
                count,
                header[0],
                header[1],
                header[2]);
    if (header[0] != DW_LOCAL_CLIENT_MAGIC || header[1] != DW_LOCAL_CLIENT_VERSION ||
        header[2] != count - 12)
    {
        std::puts("Identity record format invalid. Preserve the file.");
        return 1;
    }
    DATA_BLOB encrypted{header[2], bytes.data() + 12}, plaintext{};
    if (!CryptUnprotectData(
            &encrypted, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plaintext))
    {
        std::printf("Windows DPAPI decrypt failed: Win32=%lu. Preserve the file.\n",
                    GetLastError());
        return 1;
    }
    std::printf("Windows DPAPI decrypt passed, key blob bytes=%lu\n", plaintext.cbData);
    BCRYPT_ALG_HANDLE provider = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&provider, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
    if (status >= 0)
        status = BCryptImportKeyPair(
            provider, nullptr, BCRYPT_ECCPRIVATE_BLOB, &key, plaintext.pbData, plaintext.cbData, 0);
    SecureZeroMemory(plaintext.pbData, plaintext.cbData);
    LocalFree(plaintext.pbData);
    if (key)
        BCryptDestroyKey(key);
    if (provider)
        BCryptCloseAlgorithmProvider(provider, 0);
    std::printf("Windows P-256 key import NTSTATUS=%08lX\n", static_cast<unsigned long>(status));
    if (status < 0)
        return 1;
    std::array<uint8_t, 72> publicKey{};
    const bool native = DW_LocalIdentity_PublicKey(publicKey.data());
    SecureZeroMemory(publicKey.data(), publicKey.size());
    std::printf("Compiled identity loader: %s; stage=%s\n",
                native ? "passed" : "FAILED",
                DW_LocalIdentity_Error());
    std::puts("No private key, encrypted payload or public key is printed by this checker.");
    return native ? 0 : 1;
}
