#include "DW_LocalConfig.h"
#include "com_debugstates.h"

extern "C"
{
    __declspec(dllimport) void *__stdcall CreateFileA(
        const char *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall ReadFile(
        void *, void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) void __stdcall Sleep(unsigned long);
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *, char *, unsigned long);
}

namespace
{
    unsigned s_state = 0;
    char s_host[64] = "127.0.0.1";
    wchar_t s_wideHost[64]{};
    wchar_t s_loginPath[96]{};
    wchar_t s_headers[160]{};
    char s_authUrl[128]{}, s_nativeAuthUrl[128]{}, s_legacyUrl[160]{};
    char s_public[64]{}, s_local[64]{};
    uint16_t s_gamePort = 3074;
    char s_testCommand[112] = "replay-dw-test.command";
    char s_testEnabled[112] = "replay-dw-test.enabled";
    bool s_fieldOverflow = false;

    bool IPv4(const char *value)
    {
        for (unsigned part = 0; part < 4; ++part)
        {
            unsigned n = 0, digits = 0;
            while (*value >= '0' && *value <= '9')
            {
                n = n * 10 + unsigned(*value++ - '0');
                if (++digits > 3 || n > 255)
                    return false;
            }
            if (!digits || (part < 3 ? *value++ != '.' : *value != 0))
                return false;
        }
        return true;
    }

    void Wide(wchar_t *out, const char *text)
    {
        do
        {
            *out++ = static_cast<unsigned char>(*text);
        } while (*text++);
    }

    void Join(char *out, const char *first, const char *second, const char *third)
    {
        const char *values[] = {first, second, third};
        for (const auto *text : values)
            while (*text)
                *out++ = *text++;
        *out = 0;
    }

    bool Field(const char *line, const char *key, char *out, unsigned capacity)
    {
        unsigned i = 0;
        while (key[i] && key[i] == line[i])
            ++i;
        if (key[i] || line[i++] != '=')
            return false;
        unsigned n = 0;
        while (line[i] && line[i] != '\r' && line[i] != '\n')
        {
            if (n + 1 >= capacity)
            {
                out[0] = 0;
                s_fieldOverflow = true;
                return true;
            }
            out[n++] = line[i++];
        }
        out[n] = 0;
        return true;
    }

    void Load()
    {
        unsigned expected = 0;
        if (__atomic_compare_exchange_n(
                &s_state, &expected, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        {
            char profile[65]{}, key[65]{}, path[96]{}, headers[160]{}, port[8]{};
            // An executable-specific file allows independent native test instances.
            // Normal guest installations use replay-dw.ini in the game folder.
            char executableIni[264]{};
            const auto length = GetModuleFileNameA(nullptr, executableIni, 260);
            void *file = reinterpret_cast<void *>(~uintptr_t{0});
            if (length > 4 && length < 260 && executableIni[length - 4] == '.')
            {
                executableIni[length - 3] = 'i';
                executableIni[length - 2] = 'n';
                executableIni[length - 1] = 'i';
                file = CreateFileA(executableIni, 0x80000000, 3, nullptr, 3, 0x80, nullptr);
            }
            if (file == reinterpret_cast<void *>(~uintptr_t{0}))
                file = CreateFileA("replay-dw.ini", 0x80000000, 3, nullptr, 3, 0x80, nullptr);
            if (file != reinterpret_cast<void *>(~uintptr_t{0}))
            {
                char text[1025]{};
                unsigned long count = 0;
                const bool read = ReadFile(file, text, sizeof(text) - 1, &count, nullptr) != 0;
                CloseHandle(file);
                if (!read || count >= sizeof(text) - 1)
                    s_host[0] = 0;
                else
                    for (unsigned at = 0; at < count;)
                    {
                        Field(text + at, "host", s_host, sizeof(s_host));
                        Field(text + at, "profile", profile, sizeof(profile));
                        Field(text + at, "access_key", key, sizeof(key));
                        Field(text + at, "public_address", s_public, sizeof(s_public));
                        Field(text + at, "local_address", s_local, sizeof(s_local));
                        Field(text + at, "game_port", port, sizeof(port));
                        while (at < count && text[at] != '\n')
                            ++at;
                        if (at < count)
                            ++at;
                    }
            }
            bool valid = !s_fieldOverflow && IPv4(s_host);
            if (s_public[0] || s_local[0])
                valid = valid && IPv4(s_public) && IPv4(s_local);
            if (port[0])
            {
                unsigned value = 0;
                for (unsigned i = 0; port[i]; ++i)
                {
                    if (port[i] < '0' || port[i] > '9')
                    {
                        valid = false;
                        break;
                    }
                    value = value * 10 + unsigned(port[i] - '0');
                }
                if (value < 1024 || value > 65535)
                    valid = false;
                else
                    s_gamePort = static_cast<uint16_t>(value);
            }
            unsigned keyLength = 0;
            for (; key[keyLength]; ++keyLength)
                valid = valid && ((key[keyLength] >= 'a' && key[keyLength] <= 'f') ||
                                  (key[keyLength] >= '0' && key[keyLength] <= '9'));
            valid = valid && (keyLength == 0 || keyLength == 64);
            for (unsigned i = 0; profile[i]; ++i)
                valid = valid && ((profile[i] >= 'a' && profile[i] <= 'z') ||
                                  (profile[i] >= '0' && profile[i] <= '9') || profile[i] == '-');
            if (!valid)
                s_host[0] = s_public[0] = s_local[0] = 0;
            if (profile[0])
            {
                Join(s_testCommand, "replay-dw-", profile, "-test.command");
                Join(s_testEnabled, "replay-dw-", profile, "-test.enabled");
            }
            Wide(s_wideHost, s_host);
            Join(path, "/platform/login", profile[0] ? "/" : "", profile);
            Wide(s_loginPath, path);
            Join(headers,
                 key[0] ? "Content-Type: application/octet-stream\r\nX-Replay-Access: "
                        : "Content-Type: application/octet-stream",
                 key,
                 "\r\n");
            Wide(s_headers, headers);
            Join(s_authUrl, "http://", s_host, ":8085/auth/");
            Join(s_nativeAuthUrl, "https://", s_host, ":8443/auth/");
            Join(s_legacyUrl, "http://", s_host, ":8085/v1.0/tokens/lsg/?client=replaylocal");
            __atomic_store_n(&s_state, 2U, __ATOMIC_RELEASE);
        }
        else
        {
            while (__atomic_load_n(&s_state, __ATOMIC_ACQUIRE) != 2)
                Sleep(1);
        }
    }
} // namespace

extern "C" const char *DW_LocalConfig_Host()
{
    Load();
    return s_host;
}

extern "C" const wchar_t *DW_LocalConfig_WideHost()
{
    Load();
    return s_wideHost;
}

extern "C" const wchar_t *DW_LocalConfig_LoginPath()
{
    Load();
    return s_loginPath;
}

extern "C" const wchar_t *DW_LocalConfig_Headers()
{
    Load();
    return s_headers;
}

extern "C" const char *DW_LocalConfig_AuthUrl()
{
    Load();
    return s_authUrl;
}

extern "C" const char *DW_LocalConfig_NativeAuthUrl()
{
    Load();
    return s_nativeAuthUrl;
}

extern "C" const char *DW_LocalConfig_LegacyUrl()
{
    Load();
    return s_legacyUrl;
}

extern "C" const char *DW_LocalConfig_TestCommand()
{
    Load();
    return s_testCommand;
}

extern "C" const char *DW_LocalConfig_TestEnabled()
{
    Load();
    return s_testEnabled;
}

// Full native address prefix established by Replay's constructors, serializers
// and NetInit::InitLocalAddr. Preserve native relay construction and hashing.
struct DWNativeAddr
{
    uint8_t socketAddress[128];
    uint8_t relayRoute[24];
};

struct DWNativeAddressArray
{
    DWNativeAddr *data;
    uint32_t capacity, size;
};

struct DWNativeCommonAddrPrefix
{
    const void *vtable;
    uint32_t references, padding;
    DWNativeAddr local[5];
    uint32_t localCount, padding780;
    DWNativeAddr publicAddress;
    uint32_t natType, hash;
    uint8_t isSelf, padding945[3];
    uint32_t platform;
};

static_assert(sizeof(DWNativeAddr) == 152);
static_assert(sizeof(DWNativeCommonAddrPrefix) == 952);
static_assert(offsetof(DWNativeCommonAddrPrefix, publicAddress) == 784);
extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    extern uint8_t gl_14269C858[];
    void *func_1420EC270(void *, const DWNativeAddressArray *);
    void *func_1420EBBD0(void *, const DWNativeAddr *);
    void *func_1420EC5C0(void *);
    void *func_142192610(void *); // verified Replay bdRelayJoinData constructor
}

namespace
{
    void IpBytes(const char *text, uint8_t *out)
    {
        for (unsigned part = 0; part < 4; ++part)
        {
            unsigned value = 0;
            while (*text >= '0' && *text <= '9')
                value = value * 10 + unsigned(*text++ - '0');
            out[part] = static_cast<uint8_t>(value);
            if (*text == '.')
                ++text;
        }
    }
} // namespace

extern "C" void *func_1420EC390(DWNativeCommonAddrPrefix *self,
                                const DWNativeAddressArray *local,
                                const DWNativeAddr *publicAddress,
                                uint32_t natType,
                                uint32_t platform)
{
    self->references = 0;
    self->vtable = gl_14269C858;
    func_1420EC270(self->local, local);
    func_1420EBBD0(&self->publicAddress, publicAddress);
    self->natType = natType;
    self->isSelf = 1;
    self->platform = platform;
    func_142192610(reinterpret_cast<uint8_t *>(self) + 952);
    Load();
    if (DW_LocalBackend_IsEnabled() && s_public[0] && platform == 101)
    {
        uint8_t lan[4]{}, external[4]{};
        IpBytes(s_local, lan);
        IpBytes(s_public, external);
        for (unsigned i = 0; i < self->localCount && i < 5; ++i)
        {
            const auto *address = self->local[i].socketAddress;
            bool matches = address[0] == 2 && address[1] == 0 &&
                           ((unsigned(address[2]) << 8) | address[3]) == s_gamePort;
            for (unsigned j = 0; j < 4; ++j)
                matches = matches && address[4 + j] == lan[j];
            if (!matches)
                continue;
            auto *published = self->publicAddress.socketAddress;
            published[0] = 2;
            published[1] = 0;
            published[2] = static_cast<uint8_t>(s_gamePort >> 8);
            published[3] = static_cast<uint8_t>(s_gamePort);
            for (unsigned j = 0; j < 4; ++j)
                published[4 + j] = external[j];
            self->natType = 1;
            break;
        }
    }
    func_1420EC5C0(self);
    return self;
}
