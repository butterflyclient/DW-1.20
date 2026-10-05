#include <windows.h>
#include "account_services.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <limits>
#include <algorithm>
#include <chrono>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        std::string component(std::span<const uint8_t> bytes, size_t capacity)
        {
            wire::require(!bytes.empty() && bytes.size() < capacity);
            std::string value(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            wire::require(value != "." && value != "..");
            for (unsigned char c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return value;
        }

        Json document(const std::filesystem::path &path, size_t limit)
        {
            if (!std::filesystem::exists(path))
                return Json::object();
            wire::require(std::filesystem::file_size(path) <= limit);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Account document read failed");
            auto value = Json::parse(stream);
            wire::require(value.is_object());
            return value;
        }

        void publish(const std::filesystem::path &path, const Json &value, size_t limit)
        {
            const auto bytes = value.dump();
            wire::require(bytes.size() <= limit);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("Account document persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Account document publication failed");
        }

        Reply userState(const std::filesystem::path &directory,
                        const platform::LobbyIdentity &id,
                        wire::Reader &p)
        {
            // bdGetUserStateRequest: field 1 context. bdGetUserStateResponse: field 1
            // a JSON string (capacity 4097). Identity comes from the lobby session.
            proto::Reader reader{p.structure(1024)};
            proto::Field f;
            std::string context;
            while (reader.next(f))
                if (f.tag == 1)
                {
                    wire::require(f.type == 2 && context.empty());
                    context = component(f.bytes, 21);
                }
            wire::require(!context.empty());
            const auto path = directory / "achievement-user-state" / std::to_string(id.titleId) /
                              context / (std::to_string(id.userId) + ".json");
            const auto state = document(path, 4096);
            const auto json = state.dump();
            wire::require(json.size() <= 4096);
            // A new local account has no claimed battlepasses, tutorial rewards or XP
            // boosts. Missing optional keys leave the native progression defaults intact.
            if (!std::filesystem::exists(path))
                publish(path, state, 4096);
            Reply reply{0, {}, "achievement-user-state-read", true, {}};
            proto::text(reply.structure, 1, json);
            return reply;
        }

        struct StatRow
        {
            uint32_t board = 0;
            uint64_t owner = 0;
            uint8_t mode = 0;
            std::optional<int64_t> rating;
            std::vector<std::optional<int32_t>> columns;
        };

        template <class T> std::optional<T> statValue(wire::Reader &p, uint8_t tag)
        {
            if (p.offset < p.data.size() && p.data[p.offset] == 20)
            {
                ++p.offset;
                return std::nullopt;
            }
            return p.value<T>(tag);
        }

        int64_t merge(int64_t old, int64_t value, uint8_t mode, int64_t minimum, int64_t maximum)
        {
            if (mode == 2)
                return std::max(old, value);
            if (mode == 0)
                return value;
            wire::require((value >= 0 && old <= maximum - value) ||
                          (value < 0 && old >= minimum - value));
            return old + value;
        }

        Reply writeStats(const std::filesystem::path &directory,
                         const platform::LobbyIdentity &id,
                         wire::Reader &p)
        {
            // Same-Replay bdStatsInfo base, then LeaderBoardRow<10>'s typed Int32
            // columns. The next UInt32 starts a row; NAN (20) preserves a column.
            // Replay LiveTracker_Process maps replace/add/max to 0/1/2 respectively.
            std::vector<StatRow> rows;
            while (p.more())
            {
                wire::require(rows.size() < 200);
                StatRow row;
                row.board = p.u32();
                row.owner = p.u64();
                row.mode = p.u8();
                wire::require(row.board != UINT32_MAX && row.mode <= 2);
                row.rating = statValue<int64_t>(p, 9);
                while (p.offset < p.data.size() &&
                       (p.data[p.offset] == 7 || p.data[p.offset] == 20))
                {
                    wire::require(row.columns.size() < 10);
                    row.columns.push_back(statValue<int32_t>(p, 7));
                }
                rows.push_back(std::move(row));
            }
            p.end();
            wire::require(!rows.empty());
            for (const auto &row : rows)
                if (row.owner != id.userId)
                    return {101, {}, "stats-owner-denied"};
            const auto path = directory / "leaderboard-stats" / std::to_string(id.titleId) /
                              (std::to_string(id.userId) + ".json");
            auto data = document(path, 256 * 1024);
            for (const auto &row : rows)
            {
                const auto key = std::to_string(row.board);
                auto &target = data[key];
                if (target.is_null())
                    target = Json{{"rating", nullptr}, {"columns", Json::array()}};
                wire::require(target.is_object() && target.contains("rating") &&
                              target.at("columns").is_array());
                auto &rating = target["rating"];
                if (row.rating)
                    rating = rating.is_null() ? *row.rating
                                              : merge(rating.get<int64_t>(),
                                                      *row.rating,
                                                      row.mode,
                                                      std::numeric_limits<int64_t>::min(),
                                                      std::numeric_limits<int64_t>::max());
                auto &columns = target["columns"];
                wire::require(columns.size() <= 10);
                while (columns.size() < row.columns.size())
                    columns.push_back(nullptr);
                for (size_t i = 0; i < row.columns.size(); ++i)
                    if (row.columns[i])
                    {
                        columns[i] = columns[i].is_null() ? *row.columns[i]
                                                          : merge(columns[i].get<int32_t>(),
                                                                  *row.columns[i],
                                                                  row.mode,
                                                                  INT32_MIN,
                                                                  INT32_MAX);
                    }
                target["name"] = id.name;
                target["updated"] =
                    static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
            }
            // Validate/merge the entire batch before one atomic publication. A denied,
            // malformed or overflowing later row never commits earlier rows.
            publish(path, data, 256 * 1024);
            return {0, {}, "leaderboard-stats-written"};
        }
    } // namespace

    std::optional<Reply> accountServices(const std::filesystem::path &directory,
                                         const platform::LobbyIdentity &id,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &p)
    {
        if (service == 125 && task == 9)
            return userState(directory, id, p);
        if (service == 4 && task == 1)
            return writeStats(directory, id, p);
        return std::nullopt;
    }
} // namespace services
