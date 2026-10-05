#include <windows.h>
#include "channel_services.h"
#include "lobby.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <chrono>
#include <fstream>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        std::string category(const proto::Field &field)
        {
            wire::require(field.type == 2 && !field.bytes.empty() && field.bytes.size() < 16);
            std::string value(reinterpret_cast<const char *>(field.bytes.data()),
                              field.bytes.size());
            for (char c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_');
            return value;
        }

        void save(const std::filesystem::path &path, const Json &state)
        {
            const auto bytes = state.dump();
            wire::require(bytes.size() <= 4 * 1024 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Channel persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Channel publication failed");
        }

        wire::Bytes info(const Json &channel)
        {
            // Replay bdChannelInfo::deserialize 0x1420FE7F0, complete native DTO.
            wire::Bytes out;
            proto::text(out, 1, channel.at("category"));
            proto::integer(out, 2, channel.at("id"));
            proto::integer(out, 3, channel.at("members").size());
            proto::integer(out, 4, 256);
            proto::integer(out, 5, channel.at("owner"));
            proto::integer(out, 6, 0);
            proto::integer(out, 7, 0);
            proto::integer(out, 8, channel.at("created"));
            return out;
        }
    } // namespace

    void initializeChannels(const std::filesystem::path &directory)
    {
        const auto root = directory / "channels";
        if (!std::filesystem::exists(root))
            return;
        for (const auto &entry : std::filesystem::directory_iterator(root))
        {
            if (!entry.is_regular_file() || entry.path().extension() != L".json")
                continue;
            wire::require(entry.file_size() <= 4 * 1024 * 1024);
            std::ifstream stream(entry.path());
            Json state;
            stream >> state;
            stream.close();
            wire::require(state.at("schema") == 1 && state.at("channels").is_object());
            bool changed = false;
            for (auto &channel : state["channels"])
            {
                wire::require(channel.at("members").is_object());
                if (!channel["members"].empty())
                {
                    channel["members"] = Json::object();
                    changed = true;
                }
            }
            if (changed)
                save(entry.path(), state);
        }
    }

    void disconnectChannels(const std::filesystem::path &directory, uint32_t title, uint64_t user)
    {
        const auto path = directory / "channels" / (std::to_string(title) + ".json");
        if (!std::filesystem::exists(path))
            return;
        wire::require(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
        std::ifstream stream(path);
        Json state;
        stream >> state;
        stream.close();
        wire::require(state.at("schema") == 1 && state.at("title") == title &&
                      state.at("channels").is_object());
        bool changed = false;
        for (auto &channel : state["channels"])
        {
            wire::require(channel.at("members").is_object());
            changed = channel["members"].erase(std::to_string(user)) != 0 || changed;
        }
        if (changed)
            save(path, state);
    }

    std::optional<Reply> channelServices(const std::filesystem::path &directory,
                                         const platform::LobbyIdentity &id,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &p)
    {
        if (service == 6 && task == 14)
        {
            // Actual Replay sendGlobalInstantMessage request 0x14212CC20.
            // Native bdLobbyService::handlePushMessage 0x142122970 selects 21,
            // then reads sender UInt64, sender name[64], and message blob[4096].
            const auto recipient = p.u64();
            const auto message = p.blob(4096);
            p.end();
            wire::require(recipient && recipient != UINT64_MAX);
            if (!platform::accountName(recipient))
                return Reply{108, {}, "instant-message-recipient-not-found"};
            if (!lobby::online(id.titleId, recipient))
                return Reply{108, {}, "instant-message-recipient-offline"};
            wire::Writer push;
            push.u32(21);
            push.u64(id.userId);
            push.text(id.name);
            push.blob(message);
            Reply reply{0, {}, "global-instant-message-routed"};
            reply.deliveries.push_back({recipient, std::move(push.data)});
            return reply;
        }
        if (service != 198 || (task < 1 || (task > 7 && task != 12)))
            return std::nullopt;
        // Request 0x142163500: category string/1, channel UInt64/2,
        // caller UInt64/3. Task 12 has only category/1. Task 6 creates a channel;
        // it is not getChannelInfo, despite the inaccurate decompiler aliases.
        proto::Reader request{p.structure(4096)};
        proto::Field f;
        unsigned seen = 0;
        std::string cat;
        uint64_t channelId = 0, user = 0;
        std::vector<std::pair<std::string, uint64_t>> queries;
        wire::Bytes message;
        uint32_t messageType = 0;
        while (request.next(f))
        {
            if (task == 7)
            {
                // 0x142163570 writes repeated field-1 request objects.
                wire::require(f.tag == 1 && f.type == 2 && queries.size() < 64);
                proto::Reader item{f.bytes};
                proto::Field part;
                unsigned fields = 0;
                std::string name;
                uint64_t channel = 0;
                while (item.next(part))
                {
                    wire::require(part.tag >= 1 && part.tag <= 3 && !(fields & (1U << part.tag)));
                    fields |= 1U << part.tag;
                    if (part.tag == 1)
                        name = category(part);
                    else
                    {
                        wire::require(part.type == 0);
                        if (part.tag == 2)
                            channel = part.value;
                        else
                            wire::require(part.value == 0);
                    }
                }
                wire::require(fields == 14 && channel != 0);
                queries.emplace_back(name, channel);
                continue;
            }
            const auto last = task == 3 ? 4U : task == 4 ? 5U : 3U;
            wire::require(f.tag >= 1 && f.tag <= last && !(seen & (1U << f.tag)));
            seen |= 1U << f.tag;
            if (f.tag == 1)
                cat = category(f);
            else if ((task == 3 && f.tag == 3) || (task == 4 && f.tag == 4))
            {
                // The native push consumer 0x14211FF60 has a 1024-byte buffer.
                wire::require(f.type == 2 && f.bytes.size() <= 1024);
                message.assign(f.bytes.begin(), f.bytes.end());
            }
            else if ((task == 3 && f.tag == 4) || (task == 4 && f.tag == 5))
            {
                wire::require(f.type == 0 && f.value <= UINT32_MAX);
                messageType = static_cast<uint32_t>(f.value);
            }
            else
            {
                wire::require(f.type == 0);
                if (f.tag == 2)
                    channelId = f.value;
                else
                    user = f.value;
            }
        }
        wire::require(task == 7 ? !queries.empty()
                                : seen == (task == 12  ? 2U
                                           : task == 3 ? 30U
                                           : task == 4 ? 62U
                                                       : 14U));
        if (task == 5)
            wire::require(user <= 256);
        else if (task != 4 && user && user != id.userId)
            return Reply{101, {}, "channel-subscriber-owner-denied"};
        wire::require(task == 6 || task == 7 || task == 12 || channelId != 0);
        const auto path = directory / "channels" / (std::to_string(id.titleId) + ".json");
        Json state = {{"schema", 1}, {"title", id.titleId}, {"channels", Json::object()}};
        if (std::filesystem::exists(path))
        {
            wire::require(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Channel read failed");
            stream >> state;
            wire::require(state.is_object() && state.at("schema") == 1 &&
                          state.at("title") == id.titleId && state.at("channels").is_object());
        }
        auto &channels = state["channels"];
        wire::require(channels.size() <= 4096);
        const auto time = now();
        const auto member = std::to_string(id.userId);
        bool changed = false;
        for (auto &channel : channels)
        {
            wire::require(channel.is_object() && channel.at("members").is_object() &&
                          channel.at("members").size() <= 256);
            auto &members = channel["members"];
            for (auto it = members.begin(); it != members.end();)
            {
                if (it.value().at("expires").get<uint64_t>() <= time)
                {
                    it = members.erase(it);
                    changed = true;
                }
                else
                    ++it;
            }
            if (task == 12 && channel.at("category") == cat && members.erase(member))
                changed = true;
        }
        Reply reply{0, {}, "channel-category-unsubscribed", true, {}};
        if (task == 7)
        {
            for (const auto &query : queries)
            {
                const auto key = query.first + ":" + std::to_string(query.second);
                if (!channels.contains(key))
                    return Reply{108, {}, "channel-not-found"};
                // Native get-channel-infos response reads repeated field-1 objects
                // using 0x142104C10 and bdChannelInfo's complete deserializer.
                proto::bytes(reply.structure, 1, info(channels[key]));
            }
            reply.operation = "channel-infos-read";
        }
        else if (task != 12)
        {
            if (!channelId)
            {
                do
                {
                    const auto bytes = crypto::random(8);
                    channelId = wire::at<uint64_t>(bytes, 0);
                } while (!channelId || channels.contains(cat + ":" + std::to_string(channelId)));
            }
            const auto key = cat + ":" + std::to_string(channelId);
            if (task == 6 && !channels.contains(key))
            {
                wire::require(channels.size() < 4096);
                channels[key] = {{"category", cat},
                                 {"id", channelId},
                                 {"owner", id.userId},
                                 {"created", time},
                                 {"members", Json::object()}};
                changed = true;
            }
            if (!channels.contains(key))
                return Reply{108, {}, "channel-not-found"};
            auto &channel = channels[key];
            auto &members = channel["members"];
            if (task == 3 || task == 4)
            {
                if (!members.contains(member) ||
                    (task == 4 && !members.contains(std::to_string(user))))
                    return Reply{101, {}, "channel-message-membership-denied"};
                // Push IDs 22/23 both use the verified V2 channel message reader.
                // No request body, member names or message bytes enter diagnostics.
                wire::Writer push;
                push.u32(task == 3 ? 22 : 23);
                push.u64(id.userId);
                push.text(id.name);
                push.text(cat);
                push.u64(channelId);
                push.blob(message);
                push.u32(messageType);
                for (auto it = members.begin(); it != members.end(); ++it)
                {
                    const auto target = std::stoull(it.key());
                    if (task == 3 || target == user)
                        reply.deliveries.push_back({target, push.data});
                }
                reply.operation = task == 3 ? "channel-message-routed" : "channel-whisper-routed";
            }
            else if (task == 5)
            {
                uint64_t count = 0;
                for (auto it = members.begin(); it != members.end() && count < user; ++it, ++count)
                {
                    wire::Bytes item;
                    // Native structured member 0x142104B00: UInt64 ID/1,
                    // name/2, UInt32 flags/3; complete bounded 64-byte name.
                    proto::integer(item, 1, std::stoull(it.key()));
                    proto::text(item, 2, it.value().at("name"));
                    proto::integer(item, 3, 0);
                    proto::bytes(reply.structure, 1, item);
                }
                reply.operation = "channel-members-read";
            }
            else if (task == 2)
            {
                if (members.erase(member))
                    changed = true;
                reply.operation = "channel-unsubscribed";
            }
            else
            {
                if (!members.contains(member) && members.size() >= 256)
                    return Reply{108, {}, "channel-full"};
                const Json entry = {{"name", id.name}, {"expires", id.expires}};
                if (!members.contains(member) || members[member] != entry)
                {
                    members[member] = entry;
                    changed = true;
                }
                reply.operation = task == 6 ? "channel-created-or-joined" : "channel-subscribed";
                // 0x1420FF500 is the bound create-channel response. It reads
                // one nested field-1 bdChannelInfo at this+32, not flat fields.
                if (task == 6)
                    proto::bytes(reply.structure, 1, info(channel));
            }
        }
        if (changed)
            save(path, state);
        return reply;
    }
} // namespace services
