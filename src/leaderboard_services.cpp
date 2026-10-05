#include "leaderboard_services.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <charconv>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        struct Row
        {
            uint64_t user = 0, rank = 0, updated = 0;
            int64_t rating = 0;
            std::string name;
            std::vector<int32_t> columns;
        };

        Json document(const std::filesystem::path &path)
        {
            wire::require(std::filesystem::file_size(path) <= 256 * 1024);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Leaderboard read failed");
            auto result = Json::parse(stream);
            wire::require(result.is_object());
            return result;
        }

        std::vector<Row> rows(const std::filesystem::path &directory,
                              const platform::LobbyIdentity &id,
                              uint32_t board)
        {
            std::vector<Row> result;
            const auto root = directory / "leaderboard-stats" / std::to_string(id.titleId);
            if (!std::filesystem::exists(root))
                return result;
            size_t files = 0;
            for (const auto &entry : std::filesystem::directory_iterator(root))
            {
                if (!entry.is_regular_file() || entry.path().extension() != L".json")
                    continue;
                wire::require(++files <= 10000);
                const auto owner = entry.path().stem().string();
                uint64_t user = 0;
                const auto parsed =
                    std::from_chars(owner.data(), owner.data() + owner.size(), user);
                wire::require(parsed.ec == std::errc{} &&
                              parsed.ptr == owner.data() + owner.size() && user != 0);
                const auto data = document(entry.path());
                const auto key = std::to_string(board);
                if (!data.contains(key))
                    continue;
                const auto &value = data.at(key);
                wire::require(value.is_object() && value.contains("rating") &&
                              value.contains("columns") && value["columns"].is_array() &&
                              value["columns"].size() <= 10);
                Row row;
                row.user = user;
                row.rating = value["rating"].is_null() ? 0 : value["rating"].get<int64_t>();
                row.updated = value.value("updated", uint64_t{});
                row.name = value.value("name", user == id.userId ? id.name : std::string{});
                wire::require(row.name.size() < 64);
                for (const auto &column : value["columns"])
                    row.columns.push_back(column.is_null() ? 0 : column.get<int32_t>());
                row.columns.resize(10, 0);
                result.push_back(std::move(row));
            }
            std::sort(result.begin(),
                      result.end(),
                      [](const Row &a, const Row &b)
                      {
                          return a.rating != b.rating ? a.rating > b.rating : a.user < b.user;
                      });
            for (size_t i = 0; i < result.size(); ++i)
                result[i].rank = i + 1;
            return result;
        }

        wire::Bytes serialize(const Row &row, const std::set<size_t> &excluded)
        {
            // Native bdStatsInfo reader 0x14214AEE0, followed by the selected typed
            // Int32 columns in LeaderBoardRow<10>::deserialize 0x14150E900.
            wire::Writer out;
            out.u64(row.user);
            out.data.push_back(9);
            wire::raw(out.data, row.rating);
            out.u64(row.rank);
            out.text(row.name);
            const auto time =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            out.u32(row.updated && row.updated <= time
                        ? static_cast<uint32_t>(std::min(time - row.updated, uint64_t{UINT32_MAX}))
                        : 0);
            for (size_t i = 0; i < row.columns.size(); ++i)
                if (!excluded.contains(i))
                {
                    out.data.push_back(7);
                    wire::raw(out.data, row.columns[i]);
                }
            return std::move(out.data);
        }

        std::optional<std::set<size_t>> exclusions(const std::filesystem::path &directory,
                                                   uint32_t title,
                                                   uint32_t board,
                                                   const std::vector<std::string> &requested,
                                                   bool included)
        {
            std::set<size_t> indices;
            if (requested.empty())
                return indices;
            // Column names are asset data, not SDK layout. Do not guess their indices.
            const auto path = directory / "leaderboard-definitions" / std::to_string(title) /
                              (std::to_string(board) + ".json");
            if (!std::filesystem::exists(path))
                return std::nullopt;
            const auto definition = document(path);
            wire::require(definition.contains("columns") && definition["columns"].is_array() &&
                          definition["columns"].size() <= 10);
            for (const auto &name : requested)
            {
                auto found = std::find(
                    definition["columns"].begin(), definition["columns"].end(), Json(name));
                if (found == definition["columns"].end())
                    return std::nullopt;
                indices.insert(static_cast<size_t>(found - definition["columns"].begin()));
            }
            if (included)
            {
                std::set<size_t> omitted;
                for (size_t i = 0; i < 10; ++i)
                    if (!indices.contains(i))
                        omitted.insert(i);
                return omitted;
            }
            return indices;
        }
    } // namespace

    std::optional<Reply> leaderboardServices(const std::filesystem::path &directory,
                                             const platform::LobbyIdentity &id,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &p)
    {
        if (service != 4 || (task != 4 && task != 11 && task != 13 && task != 16 && task != 17))
            return std::nullopt;
        std::vector<uint64_t> users;
        std::vector<uint32_t> boards;
        std::vector<std::string> excluded;
        uint64_t firstRank = 0;
        uint32_t maximum = 0;
        if (task == 11)
        {
            // 0x142127C30: entity count + UInt64 entities, board count + UInt32
            // boards. Results use bdStatsInfoEx (0x14214AFA0), entity-major order.
            const auto count = p.u32();
            wire::require(count > 0 && count <= 200);
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto user = p.u64();
                wire::require(user != 0 && user != UINT64_MAX);
                users.push_back(user);
            }
            const auto boardCount = p.u32();
            wire::require(boardCount > 0 && boardCount <= 200 / count);
            for (uint32_t i = 0; i < boardCount; ++i)
            {
                const auto board = p.u32();
                wire::require(board != UINT32_MAX);
                boards.push_back(board);
            }
        }
        else
        {
            const auto board = p.u32();
            wire::require(board != UINT32_MAX);
            boards.push_back(board);
            if (task == 13 || task == 16)
            {
                maximum = p.u32();
                wire::require(maximum <= 200);
                for (uint32_t i = 0; i < maximum; ++i)
                {
                    const auto user = p.u64();
                    wire::require(user != 0 && user != UINT64_MAX);
                    users.push_back(user);
                }
            }
            else
            {
                firstRank = p.u64();
                maximum = p.u32();
                wire::require(firstRank > 0 && firstRank != UINT64_MAX && maximum <= 200);
            }
            const auto count = p.u32();
            wire::require(count <= 10);
            std::set<std::string> names;
            for (uint32_t i = 0; i < count; ++i)
            {
                auto name = p.text(65);
                wire::require(!name.empty() && names.insert(name).second);
                excluded.push_back(std::move(name));
            }
        }
        p.end();
        Reply reply{0, {}, "leaderboard-rows-read"};
        std::vector<std::vector<Row>> datasets;
        for (const auto board : boards)
            datasets.push_back(rows(directory, id, board));
        if (task == 11)
        {
            for (const auto user : users)
                for (size_t i = 0; i < boards.size(); ++i)
                {
                    const auto found = std::find_if(datasets[i].begin(),
                                                    datasets[i].end(),
                                                    [&](const Row &row)
                                                    {
                                                        return row.user == user;
                                                    });
                    wire::Writer item;
                    item.u32(boards[i]);
                    item.u32(found == datasets[i].end() ? 108 : 0);
                    if (found == datasets[i].end())
                        item.u64(user);
                    else
                    {
                        auto bytes = serialize(*found, {});
                        item.data.insert(item.data.end(), bytes.begin(), bytes.end());
                    }
                    reply.results.push_back(std::move(item.data));
                }
            return reply;
        }
        // Replay constructors 0x142128100/0x142128500 are the included-column
        // entity/rank variants (16/17); 13/4 are the excluded-column variants.
        const auto projection =
            exclusions(directory, id.titleId, boards[0], excluded, task == 16 || task == 17);
        if (!projection)
            return Reply{108, {}, "leaderboard-column-definition-required"};
        if (task == 13 || task == 16)
            for (const auto user : users)
            {
                const auto found = std::find_if(datasets[0].begin(),
                                                datasets[0].end(),
                                                [&](const Row &row)
                                                {
                                                    return row.user == user;
                                                });
                if (found != datasets[0].end())
                    reply.results.push_back(serialize(*found, *projection));
            }
        if (task == 4 || task == 17)
            for (const auto &row : datasets[0])
            {
                if (row.rank >= firstRank && reply.results.size() < maximum)
                    reply.results.push_back(serialize(row, *projection));
            }
        return reply;
    }
} // namespace services
