#include "channel_services.h"
#include "channel_store.h"
#include "lobby.h"
#include "protobuf.h"
#include <cassert>
#include <iostream>

namespace
{
    bool recipientOnline = true;
    channel_store::Json state;

    std::string hex(const wire::Bytes &value)
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
} // namespace

namespace platform
{
    std::optional<std::string> accountName(uint64_t user)
    {
        return user == 202 ? std::optional<std::string>("Receiver") : std::nullopt;
    }
} // namespace platform

namespace lobby
{
    bool online(uint32_t, uint64_t)
    {
        return recipientOnline;
    }
} // namespace lobby

namespace crypto
{
    Bytes random(unsigned size)
    {
        return Bytes(size, 7);
    }
} // namespace crypto

namespace channel_store
{
    Json load(const std::filesystem::path &, uint32_t)
    {
        return state;
    }

    void save(const std::filesystem::path &, uint32_t, const Json &value)
    {
        state = value;
    }

    uint32_t advance(Json &channel)
    {
        return channel["revision"].get<uint32_t>() + 1;
    }
} // namespace channel_store

int main()
{
    platform::LobbyIdentity sender;
    sender.titleId = 5800;
    sender.userId = 101;
    sender.name = "Sender";
    nlohmann::json cases = nlohmann::json::array();
    for (const auto &body : {wire::Bytes{'C', 'H', 'A', 'T', ':', 'h', 'e', 'l', 'l', 'o', 0},
                             wire::Bytes{'I', 'N', 'V', ':', 0, 0},
                             wire::Bytes{1, 0, 2, 255},
                             wire::Bytes{}})
    {
        wire::Writer request;
        request.u64(202);
        request.blob(body);
        request.data.push_back(0);
        wire::Reader reader{request.data};
        const auto reply = services::channelServices({}, sender, 6, 14, reader);
        assert(reply && !reply->error && reply->deliveries.size() == 1);
        if (body.size() >= 5 && body[0] == 'C')
            assert(reply->detail.find(
                       "message_kind=chat_whisper chat_layout=valid chat_body_bytes=5") !=
                   std::string::npos);
        assert(reply->deliveries[0].user == 202 && !reply->deliveries[0].channelId);
        wire::Reader push{reply->deliveries[0].payload};
        assert(push.u32() == 21 && push.u64() == 101 && push.text(64) == sender.name);
        assert(push.blob(4096) == body);
        assert(push.offset == push.data.size());
        cases.push_back(
            {{"event", 21}, {"body", hex(body)}, {"push", hex(reply->deliveries[0].payload)}});
    }
    for (unsigned textBytes : {0U, 499U, 500U})
    {
        wire::Bytes body{'C', 'H', 'A', 'T', ':'};
        body.resize(5 + textBytes, 'x');
        body.push_back(0);
        wire::Writer request;
        request.u64(202);
        request.blob(body);
        request.data.push_back(0);
        wire::Reader reader{request.data};
        const auto reply = services::channelServices({}, sender, 6, 14, reader);
        const bool valid = textBytes > 0 && textBytes <= 499;
        assert(reply && !reply->error && reply->deliveries.size() == 1);
        assert(reply->detail.find(valid ? "chat_layout=valid" : "chat_layout=invalid") !=
               std::string::npos);
        wire::Reader push{reply->deliveries[0].payload};
        assert(push.u32() == 21 && push.u64() == 101 && push.text(64) == sender.name);
        assert(push.blob(4096) == body); // Classification never changes messaging bytes.
    }
    for (bool online : {true, false})
    {
        recipientOnline = online;
        wire::Writer request;
        request.u64(online ? 303 : 202);
        request.blob(wire::Bytes{'C', 'H', 'A', 'T', ':', 'h', 0});
        request.data.push_back(0);
        wire::Reader reader{request.data};
        const auto reply = services::channelServices({}, sender, 6, 14, reader);
        assert(reply && reply->error == 108 && reply->deliveries.empty());
    }
    recipientOnline = true;
    const auto expires = uint64_t(0x7fffffffffffffff);
    state = {{"channels",
              {{"chat:700",
                {{"category", "chat"},
                 {"id", 700},
                 {"owner", 101},
                 {"revision", 1},
                 {"members",
                  {{"101", {{"name", "Sender"}, {"generation", 1}, {"expires", expires}}},
                   {"202", {{"name", "Receiver"}, {"generation", 1}, {"expires", expires}}}}}}}}}};
    wire::Bytes request;
    proto::text(request, 1, "chat");
    proto::integer(request, 2, 700);
    proto::integer(request, 3, 202);
    proto::bytes(request, 4, wire::Bytes{'h', 'e', 'l', 'l', 'o'});
    proto::integer(request, 5, 0x103); // Native crossplay visibility: everyone.
    wire::Writer envelope;
    envelope.data.push_back(23);
    envelope.u32(static_cast<uint32_t>(request.size()));
    envelope.data.insert(envelope.data.end(), request.begin(), request.end());
    envelope.data.push_back(0);
    wire::Reader reader{envelope.data};
    auto reply = services::channelServices({}, sender, 198, 4, reader);
    assert(reply && !reply->error && reply->deliveries.size() == 1);
    assert(reply->deliveries[0].user == 202 && reply->deliveries[0].channelMember == 101);
    cases.push_back({{"event", 23}, {"push", hex(reply->deliveries[0].payload)}});
    state["channels"]["chat:700"]["members"].erase("202");
    wire::Reader denied{envelope.data};
    reply = services::channelServices({}, sender, 198, 4, denied);
    assert(reply && reply->error == 101 && reply->deliveries.empty());
    auto &members = state["channels"]["chat:700"]["members"];
    members["202"] = {{"name", "Receiver"}, {"generation", 1}, {"expires", expires}};
    members.erase("101");
    wire::Reader deniedSender{envelope.data};
    reply = services::channelServices({}, sender, 198, 4, deniedSender);
    assert(reply && reply->error == 101 && reply->deliveries.empty());
    wire::Writer forged;
    forged.u64(202);
    forged.blob(wire::Bytes{'C', 'H', 'A', 'T', ':', 'h', 0});
    forged.u64(303); // A request cannot append a forged sender identity.
    forged.data.push_back(0);
    bool rejected = false;
    try
    {
        wire::Reader malicious{forged.data};
        services::channelServices({}, sender, 6, 14, malicious);
    }
    catch (const std::runtime_error &)
    {
        rejected = true;
    }
    assert(rejected);
    std::cout << nlohmann::json{{"cases", cases}, {"service_checks", 13}}.dump();
}
