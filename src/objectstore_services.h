#pragma once
#include "services.h"

namespace services
{
    Reply publisherMetadata(const std::filesystem::path &,
                            const platform::LobbyIdentity &,
                            wire::Reader &);
    Reply objectStore(const std::filesystem::path &,
                      const platform::LobbyIdentity &,
                      uint8_t,
                      wire::Reader &);
    void initializePublisherContent(const std::filesystem::path &, unsigned short);
    std::optional<wire::Bytes> publisherContent(const std::string &);
} // namespace services
