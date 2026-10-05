#pragma once
#include "services.h"

namespace services
{
    struct RESTRequest
    {
        uint32_t version = 0, method = 0, accept = 0, content = 0;
        std::string service, resource, operation, uri;
        bool hasBody = false;
        wire::Bytes body;
    };

    Reply rest(const std::filesystem::path &directory,
               const platform::LobbyIdentity &,
               wire::Reader &);
    wire::Bytes restResult(uint64_t transaction, const RESTResult &);
} // namespace services
