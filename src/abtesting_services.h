#pragma once
#include "services.h"

namespace services
{
    Reply abTestingEnroll(const std::filesystem::path &,
                          const platform::LobbyIdentity &,
                          const std::string &);
} // namespace services
