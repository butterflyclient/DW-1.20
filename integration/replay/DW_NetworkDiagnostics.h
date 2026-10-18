#pragma once
#include <stdint.h>

// WinHTTP ABI/constants verified against Windows SDK 10.0.26100.0 um/winhttp.h.
// Context is DWORD_PTR (uintptr_t). No callback retains caller-owned memory.
namespace DWNetworkDiagnostics
{
    using Clock = uint64_t (*)();
    using Sink = void (*)(const char *);
    using Callback = void(__stdcall *)(void *, uintptr_t, unsigned long, void *, unsigned long);
    using SetCallback = Callback(__stdcall *)(void *, Callback, unsigned long, uintptr_t);
    using SetOption = int(__stdcall *)(void *, unsigned long, void *, unsigned long);

    enum class Operation
    {
        Health,
        IdentityChallenge,
        IdentityLogin,
        IdentityRenew,
        Other
    };
    enum class Stage
    {
        Arguments,
        LoadLibrary,
        ResolveApi,
        Open,
        Timeouts,
        Connect,
        OpenRequest,
        RedirectPolicy,
        Send,
        Receive,
        QueryStatus,
        HttpStatus,
        Read,
        ReadEof,
        ShortResponse,
        LongResponse,
        ValidateBody,
        Complete
    };

    inline bool Equal(const wchar_t *left, const wchar_t *right)
    {
        if (!left || !right)
            return false;
        while (*left && *left == *right)
        {
            ++left;
            ++right;
        }
        return *left == *right;
    }
    inline Operation OperationForPath(const wchar_t *path)
    {
        if (Equal(path, L"/platform/client/challenge"))
            return Operation::IdentityChallenge;
        if (Equal(path, L"/platform/client/login"))
            return Operation::IdentityLogin;
        if (Equal(path, L"/platform/client/renew"))
            return Operation::IdentityRenew;
        return Operation::Other;
    }
    inline const char *Name(Operation value)
    {
        switch (value)
        {
        case Operation::Health:
            return "health";
        case Operation::IdentityChallenge:
            return "identity-challenge";
        case Operation::IdentityLogin:
            return "identity-login";
        case Operation::IdentityRenew:
            return "identity-renew";
        default:
            return "other";
        }
    }
    inline const char *Name(Stage value)
    {
        switch (value)
        {
        case Stage::Arguments:
            return "arguments";
        case Stage::LoadLibrary:
            return "load-library";
        case Stage::ResolveApi:
            return "resolve-api";
        case Stage::Open:
            return "open";
        case Stage::Timeouts:
            return "timeouts";
        case Stage::Connect:
            return "connect";
        case Stage::OpenRequest:
            return "open-request";
        case Stage::RedirectPolicy:
            return "redirect-policy";
        case Stage::Send:
            return "send";
        case Stage::Receive:
            return "receive";
        case Stage::QueryStatus:
            return "query-status";
        case Stage::HttpStatus:
            return "http-status";
        case Stage::Read:
            return "read";
        case Stage::ReadEof:
            return "read-eof";
        case Stage::ShortResponse:
            return "short-response";
        case Stage::LongResponse:
            return "long-response";
        case Stage::ValidateBody:
            return "validate-body";
        default:
            return "complete";
        }
    }

    struct Line
    {
        char data[352]{};
        unsigned length = 0;
        void Text(const char *value)
        {
            while (*value && length + 1 < sizeof(data))
                data[length++] = *value++;
        }
        void Number(uint64_t value)
        {
            char digits[24];
            unsigned count = 0;
            do
            {
                digits[count++] = static_cast<char>('0' + value % 10);
                value /= 10;
            } while (value);
            while (count && length + 1 < sizeof(data))
                data[length++] = digits[--count];
        }
        void Field(const char *name, uint64_t value)
        {
            Text(name);
            Number(value);
        }
    };

    namespace Detail
    {
        constexpr unsigned SlotCount = 32;
        constexpr unsigned EventCount = 11;
        inline constexpr unsigned long Events[EventCount] = {
            0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x10000, 0x20000, 0x200000};
        inline constexpr const char *EventNames[EventCount] = {
            "dns-start",   "dns-resolved", "connect-start", "connected",
            "sending",     "sent",         "receive-start", "response-received",
            "tls-failure", "headers",      "request-error"};
        constexpr unsigned long Notifications = 0x002300ff;
        struct Slot
        {
            uint8_t lock = 0;
            uintptr_t id = 0;
            Clock clock = nullptr;
            uint64_t start = 0, elapsed[EventCount]{};
            uint32_t mask = 0, secureFlags = 0;
        };
        // Persistent storage makes late callbacks safe after teardown or slot reuse.
        extern Slot slots[SlotCount];
        extern uintptr_t nextId;
        inline bool Lock(Slot &slot)
        {
            return !__atomic_test_and_set(&slot.lock, __ATOMIC_ACQUIRE);
        }
        inline void Unlock(Slot &slot)
        {
            __atomic_clear(&slot.lock, __ATOMIC_RELEASE);
        }
        inline void __stdcall Status(void *, uintptr_t id, unsigned long event, void *information,
                                     unsigned long bytes)
        {
            if (!id)
                return;
            Slot &slot = slots[id % SlotCount];
            if (!Lock(slot))
                return; // Diagnostic contention never delays transport.
            if (slot.id == id)
            {
                for (unsigned i = 0; i < EventCount; ++i)
                    if (Events[i] == event)
                    {
                        if (!(slot.mask & (1u << i)))
                            slot.elapsed[i] = slot.clock() - slot.start;
                        slot.mask |= 1u << i;
                        // Only the documented DWORD secure-failure mask is inspected.
                        // Addresses, headers, and arbitrary callback buffers are ignored.
                        if (event == 0x10000 && information && bytes == sizeof(uint32_t))
                            slot.secureFlags |= *static_cast<const uint32_t *>(information);
                        break;
                    }
            }
            Unlock(slot);
        }
    } // namespace Detail

    class Request
    {
      public:
        Request(Operation operation, const char *publicHost, unsigned port, Sink sink, Clock clock,
                unsigned long processId = 0)
            : operation_(operation), sink_(sink), clock_(clock), processId_(processId),
              start_(clock())
        {
            id_ = __atomic_add_fetch(&Detail::nextId, uintptr_t{1}, __ATOMIC_RELAXED);
            if (!id_)
                id_ = __atomic_add_fetch(&Detail::nextId, uintptr_t{1}, __ATOMIC_RELAXED);
            auto &slot = Detail::slots[id_ % Detail::SlotCount];
            if (Detail::Lock(slot))
            {
                if (!slot.id)
                {
                    slot.id = id_;
                    slot.clock = clock_;
                    slot.start = start_;
                    slot.mask = slot.secureFlags = 0;
                    leased_ = true;
                }
                Detail::Unlock(slot);
            }
            Line line;
            Prefix(line, "begin");
            line.Text(" host=");
            // Public endpoint only; sanitize and bound even a malformed configuration.
            unsigned i = 0;
            for (; publicHost && publicHost[i] && i < 63; ++i)
            {
                const char c = publicHost[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      c == '.' || c == '-' || c == ':'))
                    break;
                char one[2]{c, 0};
                line.Text(one);
            }
            line.Field(" port=", port);
            sink_(line.data);
        }
        Request(const Request &) = delete;
        Request &operator=(const Request &) = delete;
        uintptr_t Context() const
        {
            return attached_ ? id_ : 0;
        }
        void Begin(Stage stage)
        {
            stage_ = stage;
            stageStart_ = clock_();
        }
        void End(bool success, unsigned long error, unsigned long status = 0, unsigned received = 0,
                 unsigned expected = 0)
        {
            // One read stage can consist of many chunks: retain one bounded summary.
            if (stage_ == Stage::Read)
            {
                ++readCalls_;
                readMilliseconds_ += clock_() - stageStart_;
                if (success)
                    return;
            }
            Line line;
            Prefix(line, "stage");
            line.Text(" stage=");
            line.Text(Name(stage_));
            line.Field(" ms=", clock_() - stageStart_);
            line.Field(" ok=", success);
            line.Field(" win32=", error);
            line.Field(" http=", status);
            line.Field(" received=", received);
            line.Field(" expected=", expected);
            sink_(line.data);
        }
        void Attach(void *handle, SetOption option, SetCallback callback)
        {
            if (!leased_ || !option || !callback)
                return;
            uintptr_t context = id_;
            if (option(handle, 45, &context, sizeof(context)) &&
                callback(handle, Detail::Status, Detail::Notifications, 0) !=
                    reinterpret_cast<Callback>(~uintptr_t{0}))
            {
                attached_ = true;
                handle_ = handle;
                callback_ = callback;
            }
        }
        void Detach()
        {
            if (attached_)
            {
                // WinHTTP can still dispatch a callback already in flight. It holds
                // only an integer ID and persistent registry storage, never `this`.
                callback_(handle_, nullptr, 0, 0);
                attached_ = false;
            }
        }
        // expected == 0 denotes a variable-length response (for example health).
        void Complete(bool success, unsigned long error, unsigned long status, unsigned received,
                      unsigned expected, unsigned extra)
        {
            Detach();
            Line line;
            Prefix(line, "end");
            line.Text(" stage=");
            line.Text(Name(stage_));
            line.Field(" total_ms=", clock_() - start_);
            line.Field(" ok=", success);
            line.Field(" win32=", error);
            line.Field(" http=", status);
            line.Field(" received=", received);
            line.Field(" expected=", expected);
            line.Field(" extra=", extra);
            line.Field(" read_ms=", readMilliseconds_);
            line.Field(" read_calls=", readCalls_);
            line.Field(" callback=", leased_ && handle_ != nullptr);
            sink_(line.data);
            Release();
        }
        ~Request()
        {
            Detach();
            Release();
        }

      private:
        void Prefix(Line &line, const char *kind) const
        {
            line.Text("DW_NETWORK ");
            line.Text(kind);
            line.Field(" process=", processId_);
            line.Field(" request=", id_);
            line.Text(" operation=");
            line.Text(Name(operation_));
        }
        void Release()
        {
            if (!leased_)
                return;
            auto &slot = Detail::slots[id_ % Detail::SlotCount];
            // Worker-thread teardown only: never call this from a game-frame hot path.
            // Callback critical sections are bounded clock reads, arithmetic and stores.
            while (!Detail::Lock(slot))
            {
            }
            const uint32_t mask = slot.mask, secureFlags = slot.secureFlags;
            uint64_t elapsed[Detail::EventCount]{};
            for (unsigned i = 0; i < Detail::EventCount; ++i)
                elapsed[i] = slot.elapsed[i];
            slot.id = 0;
            Detail::Unlock(slot);
            leased_ = false;
            for (unsigned i = 0; i < Detail::EventCount; ++i)
                if (mask & (1u << i))
                {
                    Line line;
                    Prefix(line, "event");
                    line.Text(" event=");
                    line.Text(Detail::EventNames[i]);
                    line.Field(" ms=", elapsed[i]);
                    if (Detail::Events[i] == 0x10000)
                        line.Field(" secure_flags=", secureFlags);
                    sink_(line.data);
                }
        }
        Operation operation_;
        Sink sink_;
        Clock clock_;
        unsigned long processId_ = 0;
        uintptr_t id_ = 0;
        uint64_t start_, stageStart_ = 0;
        uint64_t readMilliseconds_ = 0;
        unsigned readCalls_ = 0;
        Stage stage_ = Stage::Arguments;
        bool leased_ = false, attached_ = false;
        void *handle_ = nullptr;
        SetCallback callback_ = nullptr;
    };
} // namespace DWNetworkDiagnostics
