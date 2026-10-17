#pragma once
#include "host_os.h"
#include <filesystem>
#include <chrono>

namespace tls_transport
{
    // Optional Linux HTTPS listener. Existing Windows loopback fixtures stay HTTP.
    void initialize(const std::filesystem::path &directory, unsigned portOffset);
    bool enabled();
    bool required();
    bool legacyUpdatesAllowed();
    unsigned short port();
    bool active();
    using Deadline = std::chrono::steady_clock::time_point;
    int receive(SOCKET socket, char *data, int size, Deadline deadline);
    int send(SOCKET socket, const char *data, int size, Deadline deadline);
    class Connection
    {
        void *session = nullptr;
      public:
        explicit Connection(SOCKET socket);
        ~Connection();
        Connection(const Connection &) = delete;
        Connection &operator=(const Connection &) = delete;
    };
}
