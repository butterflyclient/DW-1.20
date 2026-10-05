#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

namespace network
{
    void initialize(const std::filesystem::path &directory);
    uint32_t bindAddress();
    uint32_t advertisedAddress();
    std::array<uint8_t, 4> advertisedBytes();
    std::string httpOrigin(uint16_t port);
    uint16_t qosPort();
    uint16_t relayPort();
    uint16_t bandwidthPort();
    bool permittedPeer(uint32_t address);
    bool loginPermitted(bool loopback, const std::string &profile, const std::string &credential);
} // namespace network
