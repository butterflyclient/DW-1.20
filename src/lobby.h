#pragma once
#include "crypto.h"
#include <functional>
#include <string>
#include <atomic>

namespace lobby
{
    struct IO
    {
        std::function<bool(std::span<uint8_t>)> read;
        std::function<bool(std::span<const uint8_t>)> write;
        std::function<void(const std::string &)> log;
    };

    void serve(const IO &io);
    bool online(uint32_t title, uint64_t user);
    bool sessionOnline(uint32_t title, uint64_t user, const std::string &fingerprint);
    extern std::atomic<unsigned> connections, authenticated, frames, tasks, failures;
} // namespace lobby
