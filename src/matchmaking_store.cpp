#include <windows.h>
#include "matchmaking_store.h"
#include <algorithm>
#include <charconv>
#include <memory>
#include <set>
#include <stdexcept>

namespace matchmaking_store
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t documentLimit = 128 * 1024;
        constexpr size_t journalLimit = 32 * 1024 * 1024;
        constexpr size_t entryLimit = 202; // Lobby, at most 200 searches, player index.

        void require(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid matchmaking transaction state");
        }

        uint64_t number(const std::string &text)
        {
            uint64_t value = 0;
            const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
            require(result.ec == std::errc{} && result.ptr == text.data() + text.size() && value &&
                    std::to_string(value) == text);
            return value;
        }

        Json parse(const std::string &bytes)
        {
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto callback = [&](int, Json::parse_event_t event, Json &value)
            {
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto value = Json::parse(bytes, callback, false);
            require(unique && value.is_object());
            return value;
        }

        Json read(const std::filesystem::path &path)
        {
            const auto handle = CreateFileW(path.c_str(),
                                            GENERIC_READ,
                                            FILE_SHARE_READ,
                                            nullptr,
                                            OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Matchmaking transaction read failed");
            const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
            LARGE_INTEGER size{};
            require(GetFileSizeEx(handle, &size) && size.QuadPart >= 0 &&
                    static_cast<uint64_t>(size.QuadPart) <= journalLimit);
            std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
            DWORD received = 0;
            if (!bytes.empty() &&
                (!ReadFile(
                     handle, bytes.data(), static_cast<DWORD>(bytes.size()), &received, nullptr) ||
                 received != bytes.size()))
                throw std::runtime_error("Matchmaking transaction snapshot read failed");
            return parse(bytes);
        }

        void write(const std::filesystem::path &path, const Json &document)
        {
            const auto bytes = document.dump();
            require(bytes.size() <= journalLimit);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Matchmaking transaction write failed");
            {
                const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Matchmaking transaction flush failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Matchmaking transaction publication failed");
        }

        void validateEntry(const Write &entry, uint32_t title)
        {
            const auto &state = entry.document;
            require(state.is_object() && state.at("schema") == 1 && state.at("title") == title &&
                    state.dump().size() <= documentLimit);
            if (entry.path == "current-lobbies.json")
            {
                require(state.at("user") == 0 && state.at("revision").is_number_unsigned() &&
                        state.at("lobbies").is_object() && state["lobbies"].size() <= 4096);
                for (const auto &assignment : state["lobbies"].items())
                {
                    (void)number(assignment.key());
                    require(assignment.value().is_number_unsigned() &&
                            assignment.value().get<uint64_t>());
                }
                return;
            }
            const auto slash = entry.path.find('/');
            require(slash != std::string::npos && entry.path.ends_with(".json"));
            const auto kind = entry.path.substr(0, slash);
            const auto id = number(entry.path.substr(slash + 1, entry.path.size() - slash - 6));
            require((kind == "lobbies" || kind == "searches") &&
                    state.at("id").is_number_unsigned() && state["id"] == id &&
                    state.at("expires").is_number_unsigned());
            if (kind == "searches")
            {
                require(state.at("user").is_number_unsigned() && state["user"].get<uint64_t>() &&
                        state.at("revision").is_number_unsigned() &&
                        state.at("lobby_id").is_number_unsigned() &&
                        state["lobby_id"].get<uint64_t>() && state.at("query").is_object() &&
                        state.at("active").is_boolean());
                return;
            }
            require(state.at("owner").is_number_unsigned() && state["owner"].get<uint64_t>() &&
                    state.at("update_id").is_number_unsigned() &&
                    state["update_id"].get<uint64_t>() && state.at("members").is_array() &&
                    !state["members"].empty() && state["members"].size() <= 200 &&
                    state.at("host_doc").is_object() && state.at("backend_doc").is_object() &&
                    state["host_doc"].dump().size() < 16384 &&
                    state["backend_doc"].dump().size() < 16384 &&
                    state["host_doc"].at("listen_server").at("host_player_id") == state["owner"] &&
                    state["host_doc"]["listen_server"].at("host_address").is_string() &&
                    state["backend_doc"].at("lobby_id") == id &&
                    (!state.contains("disbanded") || state["disbanded"].is_boolean()));
            std::set<uint64_t> members;
            for (const auto &member : state["members"])
                require(member.is_number_unsigned() && member.get<uint64_t>() &&
                        members.insert(member.get<uint64_t>()).second);
            require(members.contains(state["owner"].get<uint64_t>()));
            if (state.contains("maximum_members"))
                require(state["maximum_members"].is_number_unsigned() &&
                        state["maximum_members"].get<uint64_t>() <= 200 &&
                        members.size() <= state["maximum_members"].get<uint64_t>());
        }

        std::vector<Write> validate(const Json &journal, uint32_t title)
        {
            require(journal.size() == 5 && journal.at("schema") == 1 &&
                    journal.at("title") == title && journal.at("revision").is_number_unsigned() &&
                    journal["revision"].get<uint64_t>() && journal.at("phase").is_string() &&
                    journal.at("writes").is_array() && journal["writes"].size() <= entryLimit);
            const bool prepared = journal["phase"] == "prepared";
            require(prepared || journal["phase"] == "applied");
            require(prepared ? !journal["writes"].empty() : journal["writes"].empty());
            std::vector<Write> entries;
            std::set<std::string> paths;
            for (const auto &entry : journal["writes"])
            {
                require(entry.is_object() && entry.size() == 2 && entry.at("path").is_string());
                Write snapshot{entry["path"].get<std::string>(), entry.at("document")};
                validateEntry(snapshot, title);
                require(paths.insert(snapshot.path).second);
                entries.push_back(std::move(snapshot));
            }
            return entries;
        }

        uint64_t recoverPending(const std::filesystem::path &root, uint32_t title)
        {
            require(root.filename() == std::to_string(title));
            const auto path = root / "transaction.json";
            if (!std::filesystem::exists(path))
                return 0;
            auto journal = read(path);
            const auto entries = validate(journal, title);
            if (journal["phase"] == "prepared")
            {
                // All paths and complete snapshots were validated first. No reader
                // under the store mutex can observe a partially applied transaction.
                for (const auto &entry : entries)
                    write(root / entry.path, entry.document);
                journal["phase"] = "applied";
                journal["writes"] = Json::array();
                // Retain a flushed completion marker. Deleting the journal could
                // resurrect an older prepared transaction after a power failure.
                write(path, journal);
            }
            return journal["revision"].get<uint64_t>();
        }
    } // namespace

    void initialize(const std::filesystem::path &directory)
    {
        const auto root = directory / "matchmaking";
        if (!std::filesystem::exists(root))
            return;
        size_t count = 0;
        for (const auto &entry : std::filesystem::directory_iterator(root))
        {
            require(entry.is_directory() && ++count <= 1024);
            const auto title = number(entry.path().filename().string());
            require(title <= UINT32_MAX);
            recover(entry.path(), static_cast<uint32_t>(title));
        }
    }

    void recover(const std::filesystem::path &root, uint32_t title)
    {
        (void)recoverPending(root, title);
    }

    void commit(const std::filesystem::path &root, uint32_t title, std::span<const Write> writes)
    {
        const auto revision = recoverPending(root, title);
        require(revision != UINT64_MAX);
        Json journal = {{"schema", 1},
                        {"title", title},
                        {"revision", revision + 1},
                        {"phase", "prepared"},
                        {"writes", Json::array()}};
        for (const auto &entry : writes)
            journal["writes"].push_back({{"path", entry.path}, {"document", entry.document}});
        (void)validate(journal, title);
        write(root / "transaction.json", journal);
        (void)recoverPending(root, title);
    }
} // namespace matchmaking_store
