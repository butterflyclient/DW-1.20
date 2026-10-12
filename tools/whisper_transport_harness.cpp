#include "host_os.h"
#include "lobby.h"
#include "services.h"
#include <atomic>
#include <cassert>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <tuple>
#include <unordered_map>

bool deliveryValid = true;

namespace services
{
    bool deliveryValid(uint32_t, const Delivery &)
    {
        return ::deliveryValid;
    }
} // namespace services

namespace platform
{
    bool valid(const LobbyIdentity &identity)
    {
        return identity.expires != 0;
    }
} // namespace platform

using crypto::Bytes;
#include "endpoint_layout.h"
std::mutex endpointMutex;
std::unordered_map<uint64_t, std::shared_ptr<PushEndpoint>> endpoints;
std::atomic<unsigned> failures{0};

struct QueueBoundary
{
    unsigned queued = 0;

    void add(uint32_t, const services::Delivery &)
    {
        ++queued;
    }
};

QueueBoundary queue;

QueueBoundary &deliveryQueue()
{
    return queue;
}

#include "endpoint_functions.h"
#include "traffic_layout.h"

namespace
{
    std::string hex(std::span<const uint8_t> value)
    {
        const char *digits = "0123456789abcdef";
        std::string out;
        for (auto byte : value)
        {
            out += digits[byte >> 4];
            out += digits[byte & 15];
        }
        return out;
    }

    services::Reply message(uint64_t recipient = 202, unsigned number = 0)
    {
        wire::Writer push;
        push.u32(21);
        push.u64(101);
        push.text("Sender");
        const auto text = "CHAT:" + std::to_string(number);
        Bytes body(text.begin(), text.end());
        body.push_back(0);
        push.blob(body);
        services::Reply reply{0, {}, "global-instant-message-routed"};
        reply.deliveries.push_back({recipient, std::move(push.data)});
        return reply;
    }

    std::shared_ptr<PushEndpoint> endpoint(uint64_t key = 1,
                                           uint64_t user = 202,
                                           uint32_t title = 5800)
    {
        auto value = std::make_shared<PushEndpoint>();
        value->identity.userId = user;
        value->identity.titleId = title;
        value->identity.expires = 1;
        endpoints[key] = value;
        return value;
    }

    Bytes receiveExact(SOCKET socket, unsigned count)
    {
        Bytes bytes(count);
        unsigned offset = 0;
        while (offset < count)
        {
            const auto received =
                recv(socket, reinterpret_cast<char *>(bytes.data() + offset), count - offset, 0);
            assert(received > 0);
            offset += received;
        }
        return bytes;
    }
} // namespace

int main()
{
    unsigned checks = 0;
    auto reply = message();
    publishInstantMessage(5800, reply);
    assert(reply.error == 108 && reply.deliveries.empty());
    assert(reply.detail.find("push_targets=0 push_written=0") != std::string::npos);
    ++checks;
    auto peer = endpoint();
    peer->writer = [](auto)
    {
        return false;
    };
    reply = message();
    publishInstantMessage(5800, reply);
    assert(reply.error == 108 && !peer->writer);
    assert(reply.detail.find("push_write_failed=1") != std::string::npos);
    ++checks;
    reply = message();
    publishInstantMessage(5800, reply);
    assert(reply.error == 108 && reply.detail.find("push_unavailable=1") != std::string::npos);
    ++checks;
    peer->writer = [](auto)
    {
        throw std::runtime_error("synthetic endpoint error");
        return true;
    };
    reply = message();
    publishInstantMessage(5800, reply);
    assert(reply.error == 108 && !peer->writer && failures == 1);
    ++checks;
    peer->writer = [](auto)
    {
        return true;
    };
    peer->identity.expires = 0;
    reply = message();
    publishInstantMessage(5800, reply);
    assert(reply.error == 108);
    ++checks;
    peer->identity.expires = 1;
    for (const auto mismatch : {uint64_t(303), uint64_t(202)})
    {
        peer->identity.titleId = mismatch == 202 ? 1234 : 5800;
        reply = message(mismatch);
        publishInstantMessage(5800, reply);
        assert(reply.error == 108 && reply.detail.find("push_targets=0") != std::string::npos);
        ++checks;
    }
    peer->identity.titleId = 5800;
    deliveryValid = false;
    reply = message();
    publishInstantMessage(5800, reply);
    assert(reply.error == 108);
    deliveryValid = true;
    ++checks;
    auto second = endpoint(2);
    second->writer = [](auto)
    {
        return false;
    };
    reply = message();
    publishInstantMessage(5800, reply);
    assert(!reply.error && reply.deliveries.empty());
    assert(reply.detail.find("push_targets=2 push_written=1") != std::string::npos);
    ++checks;
    endpoints.erase(2);
    auto delayed = message().deliveries[0];
    delayed.delayMs = 250;
    route(5800, delayed);
    assert(queue.queued == 1);
    ++checks;
    unsigned writes = 0;
    peer->writer = [&](auto)
    {
        ++writes;
        return true;
    };
    reply = message();
    reply.error = 101;
    publishInstantMessage(5800, reply);
    assert(reply.error == 101 && writes == 0 && reply.deliveries.size() == 1);
    ++checks;
    peer->identity.userId = 101;
    reply = message(101);
    publishInstantMessage(5800, reply);
    assert(!reply.error && writes == 1 && reply.deliveries.empty());
    peer->identity.userId = 202;
    ++checks;

    WSADATA data;
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    assert(listen(listener, 1) == 0);
    int length = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    const SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(connect(client, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    const SOCKET server = accept(listener, nullptr, nullptr);
    assert(server != INVALID_SOCKET);
    Traffic traffic;
    traffic.material.resize(72);
    for (unsigned i = 0; i < 72; ++i)
        traffic.material[i] = static_cast<uint8_t>(i);
    std::mutex sendMutex;
    lobby::IO transport;
    transport.write = [&](std::span<const uint8_t> packet)
    {
        size_t offset = 0;
        while (offset < packet.size())
        {
            const auto sent = send(server,
                                   reinterpret_cast<const char *>(packet.data() + offset),
                                   static_cast<int>(std::min<size_t>(7, packet.size() - offset)),
                                   0);
            if (sent <= 0)
                return false;
            offset += sent;
        }
        return true;
    };
#include "send_record.h"
    peer->writer = [&](auto bytes)
    {
        return sendRecord(2, bytes);
    };
    std::vector<std::thread> producers;
    std::atomic<unsigned> accepted = 0;
    for (unsigned thread = 0; thread < 4; ++thread)
        producers.emplace_back(
            [&, thread]
            {
                for (unsigned number = 0; number < 25; ++number)
                {
                    auto current = message(202, thread * 25 + number);
                    publishInstantMessage(5800, current);
                    assert(!current.error && current.deliveries.empty());
                    ++accepted;
                }
            });
    for (auto &thread : producers)
        thread.join();
    assert(accepted == 100 && traffic.outgoing == 101);
    nlohmann::json packets = nlohmann::json::array();
    for (unsigned index = 0; index < 100; ++index)
    {
        auto packet = receiveExact(client, 4);
        auto payload = receiveExact(client, wire::at<uint32_t>(packet, 0));
        packet.insert(packet.end(), payload.begin(), payload.end());
        packets.push_back(hex(packet));
    }
    closesocket(server);
    closesocket(client);
    closesocket(listener);
    WSACleanup();
    std::cout << nlohmann::json{{"outcome_checks", checks}, {"packets", packets}}.dump();
}
