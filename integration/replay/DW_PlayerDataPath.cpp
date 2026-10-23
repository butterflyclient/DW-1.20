// Private DW source replacement of Replay's native Documents data-root helper.
// The existing filesystem cache and player/profile consumers keep using it.
#include <stdint.h>

extern "C"
{
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
    __declspec(dllimport) int __stdcall WideCharToMultiByte(
        unsigned, unsigned long, const wchar_t *, int, char *, int, const char *, int *);
}

namespace
{
    struct KnownFolderId
    {
        uint32_t data1;
        uint16_t data2;
        uint16_t data3;
        uint8_t data4[8];
    };
    static_assert(sizeof(KnownFolderId) == 16);

    // FOLDERID_Documents preserves Windows folder redirection and OneDrive.
    constexpr KnownFolderId documents = {
        0xfdd39ad0, 0x238f, 0x46af, {0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7}};
    constexpr char replayDirectory[] = "\\Call of Duty Modern Warfare Replay";
}

extern "C" void func_1413FB0D0(char *destination, int capacity)
{
    if (!destination || capacity <= 0)
        return;
    destination[0] = 0;
    constexpr int suffixLength = sizeof(replayDirectory) - 1;
    if (capacity <= suffixLength)
        return;

    using GetKnownFolderPath = long(__stdcall *)(
        const KnownFolderId *, unsigned long, void *, wchar_t **);
    using TaskMemFree = void(__stdcall *)(void *);
    void *shell = LoadLibraryA("shell32.dll");
    void *ole = LoadLibraryA("ole32.dll");
    auto getPath = shell ? reinterpret_cast<GetKnownFolderPath>(
                               GetProcAddress(shell, "SHGetKnownFolderPath"))
                         : nullptr;
    auto freePath = ole ? reinterpret_cast<TaskMemFree>(GetProcAddress(ole, "CoTaskMemFree"))
                        : nullptr;
    if (getPath && freePath)
    {
        wchar_t *path = nullptr;
        if (getPath(&documents, 0, nullptr, &path) >= 0 && path)
        {
            // Reserve the entire suffix before conversion. An overlong path
            // fails empty instead of truncating into the unmodded game's root.
            const int length = WideCharToMultiByte(
                65001, 0, path, -1, destination, capacity - suffixLength, nullptr, nullptr);
            if (length > 0)
            {
                for (int i = 0; i <= suffixLength; ++i)
                    destination[length - 1 + i] = replayDirectory[i];
            }
            else
            {
                destination[0] = 0;
            }
        }
        if (path)
            freePath(path);
    }
    if (ole)
        FreeLibrary(ole);
    if (shell)
        FreeLibrary(shell);
}
