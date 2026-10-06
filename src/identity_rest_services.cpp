#include "identity_rest_services.h"
#include "../third_party/nlohmann/json.hpp"
#include <charconv>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        Reply result(const RESTRequest &request,
                     const char *operation,
                     uint32_t status,
                     const Json &body)
        {
            Reply reply{0, {}, operation};
            reply.rest = RESTResult{request.version, status, body.dump()};
            return reply;
        }

        Reply error(const RESTRequest &request, uint32_t status, uint32_t code, const char *message)
        {
            // Replay's 142100670 error reader maps the numeric UNO code and
            // its optional context array. Do not return transport success as
            // a substitute for a rejected account mutation.
            return result(
                request,
                "identity-rename-rejected",
                status,
                Json{{"error", {{"code", code}, {"name", "LocalAccountError"}, {"msg", message}}}});
        }

        Json body(const RESTRequest &request)
        {
            wire::require(request.hasBody && request.content == 1 && !request.body.empty() &&
                          request.body.size() <= 1024);
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto callback = [&](int depth, Json::parse_event_t event, Json &value)
            {
                wire::require(depth <= 4);
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto value = Json::parse(request.body, callback, false);
            wire::require(unique && value.is_object() && value.size() == 1 &&
                          value.contains("userName") && value["userName"].is_string());
            return value;
        }

        uint64_t pathOwner(const RESTRequest &request)
        {
            // Exact 142100230 writer: /v1.0/users/{auth-info.userID}/securedfields/
            // plus the registered client ID. No account/path/query aliases.
            constexpr std::string_view prefix = "/v1.0/users/", suffix = "/securedfields/?client=";
            wire::require(request.uri.starts_with(prefix));
            const auto end = request.uri.find(suffix, prefix.size());
            wire::require(end != std::string::npos);
            const auto owner =
                std::string_view(request.uri).substr(prefix.size(), end - prefix.size());
            uint64_t user = 0;
            const auto parsed = std::from_chars(owner.data(), owner.data() + owner.size(), user);
            wire::require(parsed.ec == std::errc{} && parsed.ptr == owner.data() + owner.size() &&
                          user && user != UINT64_MAX && owner == std::to_string(user) &&
                          request.uri.substr(end + suffix.size()) == "replaylocal");
            return user;
        }
    } // namespace

    std::optional<Reply> identityRest(const platform::LobbyIdentity &id, const RESTRequest &request)
    {
        if (request.service != "uno" || request.resource != "UserResource" ||
            request.operation != "renameUsername")
            return std::nullopt;
        wire::require(request.method == 0x505554 && request.accept == 1);
        if (pathOwner(request) != id.userId)
            return error(request, 403, 220000, "The account belongs to another player");
        const auto json = body(request);
        const auto header = request.headers.find("authorization");
        // The original writer uses TWO spaces after Bearer. Accept the usual
        // single-space form too, but reject extra tokens or whitespace.
        std::string token;
        if (header != request.headers.end())
        {
            const auto &value = header->second;
            if (value.starts_with("Bearer  "))
                token = value.substr(8);
            else if (value.starts_with("Bearer "))
                token = value.substr(7);
        }
        switch (platform::renameAccount(id, token, json["userName"].get<std::string>()))
        {
        case platform::RenameResult::Changed:
            return result(request, "identity-username-renamed", 200, Json{{"success", true}});
        case platform::RenameResult::Unchanged:
            return result(request, "identity-username-unchanged", 200, Json{{"success", true}});
        case platform::RenameResult::InvalidName:
            return error(request, 400, 214500, "Invalid local player name");
        case platform::RenameResult::NameUnavailable:
            return error(request, 409, 214500, "Local player name already in use");
        case platform::RenameResult::Unauthorized:
            return error(
                request, 403, 220000, "Access token is unavailable or not owned by this session");
        }
        throw std::runtime_error("Unknown identity rename result");
    }
} // namespace services
