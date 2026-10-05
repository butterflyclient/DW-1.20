#include <windows.h>
#include "engagement_services.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <set>

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

        std::string hex(std::span<const uint8_t> bytes)
        {
            constexpr char digits[] = "0123456789abcdef";
            std::string out;
            for (auto b : bytes)
            {
                out.push_back(digits[b >> 4]);
                out.push_back(digits[b & 15]);
            }
            return out;
        }

        std::string text(const proto::Field &f, size_t capacity)
        {
            wire::require(f.type == 2 && f.bytes.size() < capacity);
            std::string value(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(value.find('\0') == std::string::npos);
            return value;
        }

        void save(const std::filesystem::path &path, const Json &data)
        {
            const auto bytes = data.dump();
            wire::require(bytes.size() <= 4 * 1024 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Engagement persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Engagement publication failed");
        }

        Json load(const std::filesystem::path &path, const Json &initial)
        {
            if (!std::filesystem::exists(path))
                return initial;
            wire::require(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Engagement read failed");
            return Json::parse(in);
        }

        Reply messages(wire::Reader &p)
        {
            // Replay 0x142129BC0 -> startStructTask(104,6), request vtable
            // bdCommsGetMessagesRequest: context/language and location/count objects.
            // Native response 0x142114EC0 reads repeated field-1 message objects; an
            // absent collection is a valid empty publication, not invented ads.
            proto::Reader request{p.structure(16384)};
            proto::Field f;
            unsigned seen = 0, locations = 0;
            while (request.next(f))
            {
                if (f.tag == 1 || f.tag == 2)
                {
                    const auto bit = 1U << f.tag;
                    wire::require(!(seen & bit));
                    seen |= bit;
                    (void)text(f, f.tag == 1 ? 16 : 20);
                }
                else if (f.tag == 3)
                {
                    wire::require(f.type == 2 && ++locations <= 64);
                    proto::Reader location{f.bytes};
                    proto::Field l;
                    unsigned fields = 0;
                    while (location.next(l))
                        if (l.tag == 1 || l.tag == 2)
                        {
                            const auto bit = 1U << l.tag;
                            wire::require(!(fields & bit) && l.type == 0 && l.value <= UINT32_MAX);
                            fields |= bit;
                            if (l.tag == 2)
                                wire::require(l.value <= 100);
                        }
                    wire::require(fields == 6);
                }
            }
            wire::require(seen == 6);
            return {0, {}, "marketing-messages-empty", true, {}};
        }

        Reply viewed(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Same-Replay 104/7 constructor 142129C50. Request writer 142115320:
            // context (1), repeated bdCommsMessageViewed objects (2). Its 80-byte
            // object writer 142115180 emits u64 ID/u32 location/u64 assignment/text.
            proto::Reader reader{p.structure(64 * 1024)};
            proto::Field f;
            std::string context;
            bool seen = false;
            auto incoming = Json::array();
            while (reader.next(f))
            {
                wire::require(f.tag == 1 || f.tag == 2);
                if (f.tag == 1)
                {
                    wire::require(!seen);
                    seen = true;
                    context = text(f, 17);
                }
                else
                {
                    wire::require(f.type == 2 && incoming.size() < 100);
                    proto::Reader item{f.bytes};
                    proto::Field field;
                    unsigned fields = 0;
                    Json row = Json::object();
                    while (item.next(field))
                    {
                        wire::require(field.tag >= 1 && field.tag <= 4 &&
                                      !(fields & (1U << field.tag)));
                        fields |= 1U << field.tag;
                        const auto key = std::to_string(field.tag);
                        if (field.tag == 4)
                            row[key] = text(field, 21);
                        else
                        {
                            wire::require(field.type == 0 &&
                                          (field.tag != 2 || field.value <= UINT32_MAX));
                            row[key] = field.value;
                        }
                    }
                    wire::require(fields == 30);
                    incoming.push_back(std::move(row));
                }
            }
            wire::require(seen && !context.empty() && context != "." && context != "..");
            for (char c : context)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            const auto path = directory / "marketing" / std::to_string(id.titleId) / context /
                              (std::to_string(id.userId) + ".views.json");
            auto data =
                load(path, Json{{"schema", 1}, {"owner", id.userId}, {"views", Json::object()}});
            try
            {
                wire::require(data.at("schema") == 1 && data.at("owner").is_number_unsigned() &&
                              data.at("owner") == id.userId && data.at("views").is_object() &&
                              data.at("views").size() <= 4096);
                for (auto receipt = data.at("views").begin(); receipt != data.at("views").end();
                     ++receipt)
                {
                    const auto &row = receipt->at("view");
                    wire::require(row.is_object() && row.size() == 4);
                    for (const auto *key : {"1", "2", "3"})
                        wire::require(row.at(key).is_number_unsigned());
                    wire::require(row.at("2").get<uint64_t>() <= UINT32_MAX);
                    const auto language = row.at("4").get<std::string>();
                    wire::require(language.size() <= 20 &&
                                  language.find('\0') == std::string::npos);
                    wire::require(receipt->at("recorded").is_number_unsigned());
                    const auto encoded = row.dump();
                    wire::require(
                        receipt.key() ==
                        hex(crypto::sha256(std::span(
                            reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()))));
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Marketing receipt store schema invalid");
            }
            for (const auto &row : incoming)
            {
                const auto encoded = row.dump();
                const auto digest = hex(crypto::sha256(
                    std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size())));
                auto &views = data["views"];
                if (views.contains(digest))
                    continue;
                if (views.size() >= 4096)
                    return {102, {}, "marketing-view-capacity-exceeded"};
                views[digest] = Json{{"view", row}, {"recorded", now()}};
            }
            if (!incoming.empty())
                save(path, data);
            return {0, {}, "marketing-views-recorded", true, {}};
        }

        Reply enroll(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Replay 0x142139AD0 starts 194/1 using the full HTTP-proxy envelope.
            // 0x1420FF850 requires expiresIn, ABToken and enrollments JSON, and updates
            // the native lobby token lifetime itself. This local server offers no tests.
            proto::Reader request{p.structure(16384)};
            proto::Field f;
            std::string method, url;
            unsigned headers = 0, seen = 0;
            while (request.next(f))
            {
                if (f.tag == 1 || f.tag == 2)
                {
                    const auto bit = 1U << f.tag;
                    wire::require(!(seen & bit));
                    seen |= bit;
                    auto value = text(f, f.tag == 1 ? 16 : 1024);
                    if (f.tag == 1)
                        method = value;
                    else
                        url = value;
                }
                else if (f.tag == 3)
                    wire::require(f.type == 2 && f.bytes.empty());
                else if (f.tag == 4)
                {
                    wire::require(f.type == 2 && ++headers <= 16);
                    proto::Reader header{f.bytes};
                    proto::Field h;
                    while (header.next(h))
                        if (h.tag == 1 || h.tag == 2)
                            (void)text(h, h.tag == 1 ? 100 : 4096);
                }
            }
            wire::require(seen == 6 && method == "POST");
            const auto account = "/v2/users/bnet-" + std::to_string(id.userId) + "/enrollments/";
            const auto universal = "/v2/users/uno-" + std::to_string(id.userId) + "/enrollments/";
            auto route = url.find("/v2/users/");
            wire::require(route != std::string::npos);
            auto query = url.find('?', route);
            const auto path =
                url.substr(route, query == std::string::npos ? url.size() - route : query - route);
            if (path != account && path != universal)
                return {101, {}, "ab-enrollment-owner-denied"};
            const auto target = directory / "ab-enrollments" / std::to_string(id.titleId) /
                                (std::to_string(id.userId) + ".json");
            auto state = load(target, Json::object());
            if (!state.contains("expires") || state.at("expires").get<uint64_t>() <= now())
            {
                const auto token = crypto::random(32);
                constexpr char digits[] = "0123456789abcdef";
                std::string encoded;
                for (auto b : token)
                {
                    encoded.push_back(digits[b >> 4]);
                    encoded.push_back(digits[b & 15]);
                }
                state = {
                    {"token", encoded}, {"expires", now() + 3600}, {"enrollments", Json::array()}};
                save(target, state);
            }
            wire::require(state.at("enrollments").is_array() && state.at("enrollments").empty());
            const auto body = Json{{"expiresIn", state.at("expires").get<uint64_t>() - now()},
                                   {"ABToken", state.at("token")},
                                   {"enrollments", state.at("enrollments")}}
                                  .dump();
            Reply reply{0, {}, "ab-enrollment-read", true, {}};
            wire::Bytes header;
            proto::text(header, 1, "Content-Length");
            proto::text(header, 2, std::to_string(body.size()));
            proto::bytes(reply.structure, 1, header);
            proto::integer(reply.structure, 2, 200);
            proto::text(reply.structure, 3, body);
            return reply;
        }

        Reply events(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Same-Replay task constructor 0x14212DE00, serializable 0x1420FB3F0.
            const auto count = p.u32();
            wire::require(count <= 256);
            Json incoming = Json::array();
            // Native recordMixedEvents can submit a zero-event flush.
            if (!count)
            {
                p.end();
                return {0, {}, "events-empty-batch"};
            }
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto category = p.u32();
                const bool binary = p.boolean();
                wire::Bytes bytes;
                // The native task grows up to 0x40000 bytes (0x14212DE00); event
                // payloads are not limited to 8 KiB, and writeBlob accepts length zero.
                if (binary)
                    bytes = p.blob(0x40000);
                else
                {
                    const auto value = p.text(0x40000);
                    bytes.assign(value.begin(), value.end());
                }
                incoming.push_back(
                    {{"category", category}, {"binary", binary}, {"contentHex", hex(bytes)}});
            }
            p.end();
            const auto path = directory / "event-log" / std::to_string(id.titleId) /
                              (std::to_string(id.userId) + ".json");
            auto state = load(path, Json{{"nextId", 1}, {"events", Json::array()}});
            wire::require(state.is_object() && state.at("events").is_array());
            auto next = state.at("nextId").get<uint64_t>();
            wire::require(next > 0 && next <= UINT64_MAX - count);
            Reply reply{0, {}, "events-recorded"};
            // Preserve the pre-archive server's retained records before any eviction.
            if (!state.contains("archive_schema"))
            {
                if (!state.at("events").empty())
                {
                    const auto previous = state.dump();
                    const auto digest = hex(crypto::sha256(std::span(
                        reinterpret_cast<const uint8_t *>(previous.data()), previous.size())));
                    save(path.parent_path() / std::to_string(id.userId) / "batches" /
                             ("legacy-" + digest + ".json"),
                         state);
                }
                state["archive_schema"] = 1;
            }
            const auto first = next;
            for (auto &event : incoming)
            {
                event["id"] = next;
                event["recorded"] = now();
                state["events"].push_back(event);
                wire::Writer result;
                result.u64(next++);
                reply.results.push_back(std::move(result.data));
            }
            // Retain full accepted batches independently of the bounded recent-event
            // window. A native frame is at most 1 MiB, so its hex/JSON batch fits the
            // existing 4 MiB publication bound. Content-addressed names avoid replacing
            // an orphaned batch with a different retry if state publication fails.
            const auto batch = Json{{"schema", 1},
                                    {"title", id.titleId},
                                    {"owner", id.userId},
                                    {"first_id", first},
                                    {"next_id", next},
                                    {"events", incoming}};
            const auto batchBytes = batch.dump();
            const auto digest = hex(crypto::sha256(std::span(
                reinterpret_cast<const uint8_t *>(batchBytes.data()), batchBytes.size())));
            save(path.parent_path() / std::to_string(id.userId) / "batches" /
                     (std::to_string(first) + "-" + std::to_string(next - 1) + "-" + digest +
                      ".json"),
                 batch);
            auto &recorded = state["events"];
            if (recorded.size() > 256)
                recorded.erase(recorded.begin(), recorded.end() - 256);
            // Bound bytes as well as count. Previously valid native menu telemetry
            // repeatedly failed once 256 payloads approached the 4 MiB file limit.
            size_t retainedBytes = 0;
            for (const auto &event : recorded)
                retainedBytes += event.dump().size() + 1;
            size_t removed = 0;
            while (retainedBytes > 4 * 1024 * 1024 - 4096 && removed < recorded.size())
                retainedBytes -= recorded[removed++].dump().size() + 1;
            if (removed)
                recorded.erase(recorded.begin(),
                               recorded.begin() + static_cast<Json::difference_type>(removed));
            state["nextId"] = next;
            save(path, state);
            return reply;
        }
    } // namespace

    std::optional<Reply> engagementServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &id,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &p)
    {
        if (service == 104 && task == 6)
            return messages(p);
        if (service == 104 && task == 7)
            return viewed(directory, id, p);
        if (service == 194 && task == 1)
            return enroll(directory, id, p);
        if (service == 67 && task == 5)
            return events(directory, id, p);
        return std::nullopt;
    }
} // namespace services
