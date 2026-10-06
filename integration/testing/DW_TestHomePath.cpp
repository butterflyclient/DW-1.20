// Included only by the private, two-client development build. Normal DW and
// Replay builds retain the original native Documents helper and its layout.
#include <stdint.h>
#include "replay_dvar.h"

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    const char *DW_LocalConfig_TestEnabled();
    bool func_1412CF280(); // original main-thread predicate
    bool func_1412CF260(); // original database-thread predicate
    bool func_1412CF2C0(); // original render-thread predicate
    bool func_1412CF300(); // original server-thread predicate
    char *func_1413D8B10(const char *, const char *, const char *, char *);  // FS_BuildOSPath
    unsigned func_1413DA2D0(const char *, const char *, unsigned, unsigned); // native handle owner
    extern const dvar_t *gl_14E36AAD8; // fs_basepath; complete record in replay_dvar.h
    extern const dvar_t *gl_14E36A9C8; // fs_debug
    void Com_Printf(int, const char *, ...);
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
    __declspec(dllimport) void *__stdcall CreateFileA(
        const char *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) int __stdcall WideCharToMultiByte(
        unsigned, unsigned long, const wchar_t *, int, char *, int, const char *, int *);
}

namespace
{
    bool TestHome(char *, int);
}

// DCache uses FS_FOpenFileReadWrite and fs_basepath, independently of the
// profile's home path. Route only its four exact leaves in this private build.
// Native path construction, OS modes and handle/thread ownership stay native.
extern "C" unsigned func_1413D9900(const char *filename, unsigned mode)
{
    if (!filename || !gl_14E36AAD8 || !gl_14E36AAD8->current.string)
        return 0;
    const char *root = gl_14E36AAD8->current.string;
    char overridePath[256]{}, path[256]{};
    constexpr const char *cacheFiles[] = {
        "toc0.dcache", "toc1.dcache", "data0.dcache", "data1.dcache"};
    for (const auto *leaf : cacheFiles)
    {
        unsigned i = 0;
        while (leaf[i] && filename[i] == leaf[i])
            ++i;
        if (!leaf[i] && !filename[i] && TestHome(overridePath, sizeof(overridePath)))
        {
            if (!overridePath[0])
                return 0;
            root = overridePath;
            break;
        }
    }
    const unsigned thread = func_1412CF280()   ? 0U
                            : func_1412CF260() ? 1U
                            : func_1412CF2C0() ? 2U
                            : func_1412CF300() ? 3U
                                               : 5U;
    func_1413D8B10(root, "", filename, path);
    if (gl_14E36A9C8 && gl_14E36A9C8->current.integer)
        Com_Printf(10, "FS_FOpenFileReadWrite: %s\n", path);
    return func_1413DA2D0(filename, path, thread, mode != 0);
}

namespace
{
    struct KnownFolderId
    {
        uint32_t data1;
        uint16_t data2, data3;
        uint8_t data4[8];
    };

    static_assert(sizeof(KnownFolderId) == 16);
    constexpr KnownFolderId documents = {
        0xfdd39ad0, 0x238f, 0x46af, {0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7}};

    bool TestHome(char *destination, int capacity)
    {
        if (!DW_LocalBackend_IsEnabled())
            return false;
        auto flag =
            CreateFileA(DW_LocalConfig_TestEnabled(), 0x80000000, 3, nullptr, 3, 0x80, nullptr);
        if (flag == reinterpret_cast<void *>(~uintptr_t{0}))
            return false;
        CloseHandle(flag);
        auto kernel = LoadLibraryA("kernel32.dll");
        using Environment = unsigned long(__stdcall *)(const char *, char *, unsigned long);
        auto environment =
            kernel
                ? reinterpret_cast<Environment>(GetProcAddress(kernel, "GetEnvironmentVariableA"))
                : nullptr;
        const auto length =
            environment ? environment("REPLAY_DW_TEST_HOME", destination, capacity) : 0;
        if (kernel)
            FreeLibrary(kernel);
        if (!length)
            return false;
        // An invalid explicit override fails empty; it never silently opens
        // the user's normal cache or truncates into a different directory.
        bool valid = length < static_cast<unsigned>(capacity) && length >= 3 &&
                     ((destination[0] >= 'A' && destination[0] <= 'Z') ||
                      (destination[0] >= 'a' && destination[0] <= 'z')) &&
                     destination[1] == ':' && destination[2] == '\\';
        for (unsigned i = 3; valid && i < length; ++i)
            valid = static_cast<unsigned char>(destination[i]) >= 32 && destination[i] != ':';
        if (!valid)
            destination[0] = 0;
        return true;
    }
} // namespace

extern "C" void func_1413FB0D0(char *destination, int capacity)
{
    if (!destination || capacity <= 0)
        return;
    destination[0] = 0;
    if (TestHome(destination, capacity))
        return;
    destination[0] = 0;
    constexpr char suffix[] = "\\Call of Duty Modern Warfare";
    constexpr int suffixLength = sizeof(suffix) - 1;
    if (capacity <= suffixLength)
        return;
    using GetPath = long(__stdcall *)(const KnownFolderId *, unsigned long, void *, wchar_t **);
    using FreePath = void(__stdcall *)(void *);
    auto shell = LoadLibraryA("shell32.dll");
    auto ole = LoadLibraryA("ole32.dll");
    auto getPath =
        shell ? reinterpret_cast<GetPath>(GetProcAddress(shell, "SHGetKnownFolderPath")) : nullptr;
    auto freePath =
        ole ? reinterpret_cast<FreePath>(GetProcAddress(ole, "CoTaskMemFree")) : nullptr;
    if (getPath && freePath)
    {
        wchar_t *path = nullptr;
        if (getPath(&documents, 0, nullptr, &path) >= 0 && path)
        {
            const int length = WideCharToMultiByte(
                65001, 0, path, -1, destination, capacity - suffixLength, nullptr, nullptr);
            if (length > 0)
                for (int i = 0; i <= suffixLength; ++i)
                    destination[length - 1 + i] = suffix[i];
        }
        if (path)
            freePath(path);
    }
    if (ole)
        FreeLibrary(ole);
    if (shell)
        FreeLibrary(shell);
}
