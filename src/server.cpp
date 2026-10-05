#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "platform.h"
#include "platform_resources.h"
#include "lobby.h"
#include "services.h"
#include "objectstore_services.h"
#include "qos_provider.h"
#include "content_services.h"
#include "relay_services.h"
#include "relay_provider.h"
#include "network.h"

namespace
{
    constexpr unsigned maxBody = 256 * 1024;
    constexpr unsigned maxHeader = 16 * 1024;
    constexpr unsigned maxClients = 32;
    std::atomic<bool> stopping{false};
    std::atomic<unsigned> active{0}, probes{0}, authRequests{0};
    std::mutex logMutex;
    std::ofstream logFile;

    void log(const std::string &message)
    {
        std::lock_guard lock(logMutex);
        const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        tm utc{};
        gmtime_s(&utc, &now);
        char stamp[32]{};
        std::strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
        std::printf("%s %s\n", stamp, message.c_str());
        logFile << stamp << ' ' << message << '\n';
        logFile.flush();
    }

    struct Socket
    {
        SOCKET value = INVALID_SOCKET;

        explicit Socket(SOCKET socket = INVALID_SOCKET) : value(socket) {}

        ~Socket()
        {
            if (value != INVALID_SOCKET)
                closesocket(value);
        }

        Socket(const Socket &) = delete;
        Socket &operator=(const Socket &) = delete;
    };

    bool sendAll(SOCKET socket, const std::string &bytes)
    {
        size_t sent = 0;
        while (sent < bytes.size())
        {
            const int n =
                send(socket, bytes.data() + sent, static_cast<int>(bytes.size() - sent), 0);
            if (n <= 0)
                return false;
            sent += static_cast<unsigned>(n);
        }
        return true;
    }

    bool receiveExact(SOCKET socket, void *target, unsigned size)
    {
        auto *bytes = static_cast<char *>(target);
        unsigned at = 0;
        while (at < size && !stopping.load())
        {
            const int n = recv(socket, bytes + at, static_cast<int>(size - at), 0);
            if (n <= 0)
                return false;
            at += static_cast<unsigned>(n);
        }
        return at == size;
    }

    void reply(SOCKET socket,
               unsigned status,
               const std::string &body,
               const char *contentType = "application/json",
               const std::string &extraHeaders = "")
    {
        const char *reason = status == 200   ? "OK"
                             : status == 201 ? "Created"
                             : status == 206 ? "Partial Content"
                             : status == 400 ? "Bad Request"
                             : status == 404 ? "Not Found"
                             : status == 416 ? "Range Not Satisfiable"
                             : status == 409 ? "Conflict"
                             : status == 503 ? "Service Unavailable"
                             : status == 500 ? "Internal Server Error"
                                             : "Not Implemented";
        sendAll(socket,
                "HTTP/1.1 " + std::to_string(status) + " " + reason +
                    "\r\nContent-Type: " + contentType +
                    "\r\nCache-Control: no-store\r\n"
                    "Connection: close\r\n" +
                    extraHeaders + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" +
                    body);
    }

    std::string status()
    {
        return "{\"server\":\"iw8-dw\",\"build\":\"replay120\",\"protocol_revision\":1,"
               "\"stage\":\"transport-ready\",\"capability_stage\":\"encrypted-lobby-profiles\","
               "\"native_auth\":true,\"native_tasks\":true,"
               "\"profiles\":true,\"storage\":true,\"matchmaking\":false,\"native_game_verified\":"
               "false,\"platform_auth\":true,\"platform_logins\":" +
               std::to_string(platform::logins()) +
               ",\"platform_sessions\":" + std::to_string(platform::sessions()) +
               ",\"probes\":" + std::to_string(probes.load()) +
               ",\"auth_requests\":" + std::to_string(authRequests.load()) +
               ",\"auth_successes\":" + std::to_string(platform::authentications()) +
               ",\"legacy_logins\":" + std::to_string(platform::legacyLogins()) +
               ",\"lobby_authenticated\":" + std::to_string(lobby::authenticated.load()) +
               ",\"tasks\":" + std::to_string(lobby::tasks.load()) +
               ",\"lobby_failures\":" + std::to_string(lobby::failures.load()) +
               ",\"lobby_frames\":" + std::to_string(lobby::frames.load()) +
               ",\"local_qos_enabled\":" + (qos_provider::enabled() ? "true" : "false") +
               ",\"local_qos_probes\":" + std::to_string(qos_provider::probes()) +
               ",\"local_nat_introductions\":" + std::to_string(qos_provider::traversals()) +
               ",\"relay\":" + relay_provider::status() + "}";
    }

    std::string lower(std::string value)
    {
        for (char &c : value)
            if (c >= 'A' && c <= 'Z')
                c += 'a' - 'A';
        return value;
    }

    struct ContentRange
    {
        size_t first = 0, last = 0;
    };

    std::optional<ContentRange> contentRange(const std::string &header, size_t size)
    {
        if (!size || !header.starts_with("bytes="))
            return std::nullopt;
        const auto text = header.substr(6);
        const auto dash = text.find('-');
        if (dash == std::string::npos || text.find('-', dash + 1) != std::string::npos)
            return std::nullopt;
        auto number = [](const std::string &value, size_t &out)
        {
            if (value.empty())
                return false;
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), out);
            return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size();
        };
        ContentRange range;
        range.last = size - 1;
        if (!dash)
        {
            size_t suffix = 0;
            if (!number(text.substr(1), suffix) || !suffix)
                return std::nullopt;
            range.first = suffix >= size ? 0 : size - suffix;
        }
        else
        {
            if (!number(text.substr(0, dash), range.first) || range.first >= size)
                return std::nullopt;
            if (dash + 1 < text.size() &&
                (!number(text.substr(dash + 1), range.last) || range.last < range.first))
                return std::nullopt;
            range.last = std::min(range.last, size - 1);
        }
        return range;
    }

    void http(SOCKET socket)
    {
        std::string request;
        std::array<char, 4096> buffer{};
        size_t headerEnd = std::string::npos;
        while ((headerEnd = request.find("\r\n\r\n")) == std::string::npos)
        {
            const int n = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (n <= 0)
                return;
            request.append(buffer.data(), static_cast<size_t>(n));
            if (request.size() > maxHeader + buffer.size())
            {
                reply(socket, 400, "{\"error\":\"header_too_large\"}");
                return;
            }
        }
        if (headerEnd > maxHeader)
        {
            reply(socket, 400, "{\"error\":\"header_too_large\"}");
            return;
        }
        const size_t firstLineEnd = request.find("\r\n");
        std::istringstream first(request.substr(0, firstLineEnd));
        std::string method, path, version, trailing;
        first >> method >> path >> version;
        if (method.empty() || path.empty() || version != "HTTP/1.1" || first >> trailing)
        {
            reply(socket, 400, "{\"error\":\"invalid_request\"}");
            return;
        }
        const auto bodyLimit = (method == "PUT" && path.starts_with("/content-streaming/upload/"))
                                   ? services::maximumStreamingBody
                                   : maxBody;
        unsigned length = 0;
        bool hasLength = false;
        std::optional<std::string> rangeHeader;
        std::optional<std::string> destinationHeader;
        std::optional<std::string> accessHeader;
        size_t at = firstLineEnd + 2;
        while (at < headerEnd)
        {
            const size_t end = request.find("\r\n", at);
            const auto colon = request.find(':', at);
            if (colon >= end)
            {
                reply(socket, 400, "{\"error\":\"invalid_header\"}");
                return;
            }
            const std::string key = lower(request.substr(at, colon - at));
            const size_t valueAt = request.find_first_not_of(" \t", colon + 1);
            const std::string value = valueAt < end ? request.substr(valueAt, end - valueAt) : "";
            if (key == "transfer-encoding")
            {
                reply(socket, 400, "{\"error\":\"transfer_encoding_unsupported\"}");
                return;
            }
            if (key == "content-length")
            {
                const auto result =
                    std::from_chars(value.data(), value.data() + value.size(), length);
                if (hasLength || result.ec != std::errc{} ||
                    result.ptr != value.data() + value.size() || length > bodyLimit)
                {
                    reply(socket, 400, "{\"error\":\"invalid_content_length\"}");
                    return;
                }
                hasLength = true;
            }
            if (key == "range")
            {
                if (rangeHeader)
                {
                    reply(socket, 400, "{\"error\":\"duplicate_range\"}");
                    return;
                }
                rangeHeader = value;
            }
            if (key == "destination")
            {
                if (destinationHeader)
                {
                    reply(socket, 400, "{\"error\":\"duplicate_destination\"}");
                    return;
                }
                destinationHeader = value;
            }
            if (key == "x-replay-access")
            {
                if (accessHeader || value.size() > 64)
                {
                    reply(socket, 400, "{\"error\":\"invalid_access_header\"}");
                    return;
                }
                accessHeader = value;
            }
            at = end + 2;
        }
        const size_t bodyAt = headerEnd + 4;
        while (request.size() - bodyAt < length)
        {
            const unsigned remaining = length - static_cast<unsigned>(request.size() - bodyAt);
            const int n = recv(socket,
                               buffer.data(),
                               static_cast<int>(std::min<unsigned>(
                                   remaining, static_cast<unsigned>(buffer.size()))),
                               0);
            if (n <= 0)
                return;
            request.append(buffer.data(), static_cast<size_t>(n));
        }
        if (request.size() - bodyAt != length)
        {
            reply(socket, 400, "{\"error\":\"unexpected_request_bytes\"}");
            return;
        }
        if (method == "GET" && (path == "/health" || path == "/status"))
        {
            ++probes;
            reply(socket, 200, status());
        }
        else if (method == "COPY" && path.starts_with("/content-streaming/copy/"))
        {
            if (!destinationHeader || length || rangeHeader)
            {
                reply(socket, 400, "{\"error\":\"invalid_copy_request\"}");
                return;
            }
            try
            {
                const auto status = services::streamingCopy(path, *destinationHeader);
                reply(socket, status, status < 300 ? "" : "{\"error\":\"copy_rejected\"}");
            }
            catch (const std::exception &)
            {
                reply(socket, 500, "{\"error\":\"copy_storage_failed\"}");
            }
        }
        else if (method == "PUT" && path.starts_with("/content-streaming/upload/"))
        {
            if (!hasLength || rangeHeader)
            {
                reply(socket, 400, "{\"error\":\"whole_upload_content_length_required\"}");
                return;
            }
            try
            {
                const auto status = services::streamingUpload(
                    path,
                    std::span(reinterpret_cast<const uint8_t *>(request.data() + bodyAt), length));
                reply(socket,
                      status,
                      status == 200 ? "" : "{\"error\":\"streaming_upload_rejected\"}",
                      "application/octet-stream");
                log("STREAMING upload status=" + std::to_string(status) +
                    " bytes=" + std::to_string(length));
            }
            catch (const std::exception &)
            {
                reply(socket, 500, "{\"error\":\"streaming_upload_unavailable\"}");
            }
        }
        else if (method == "GET" && (path.starts_with("/objectstore/content/") ||
                                     path.starts_with("/content-streaming/download/")))
        {
            try
            {
                const auto content = path.starts_with("/content-streaming/")
                                         ? services::streamingContent(path)
                                         : services::publisherContent(path);
                if (!content)
                    reply(socket, 404, "{\"error\":\"publisher_content_not_found\"}");
                else
                {
                    if (rangeHeader)
                    {
                        const auto range = contentRange(*rangeHeader, content->size());
                        if (!range)
                            reply(socket,
                                  416,
                                  "",
                                  "application/octet-stream",
                                  "Content-Range: bytes */" + std::to_string(content->size()) +
                                      "\r\n");
                        else
                        {
                            const auto size = range->last - range->first + 1;
                            reply(socket,
                                  206,
                                  std::string(reinterpret_cast<const char *>(content->data() +
                                                                             range->first),
                                              size),
                                  "application/octet-stream",
                                  "Accept-Ranges: bytes\r\nContent-Range: bytes " +
                                      std::to_string(range->first) + "-" +
                                      std::to_string(range->last) + "/" +
                                      std::to_string(content->size()) + "\r\n");
                            log("PUBLISHER immutable range download bytes=" + std::to_string(size));
                        }
                    }
                    else
                    {
                        reply(socket,
                              200,
                              std::string(reinterpret_cast<const char *>(content->data()),
                                          content->size()),
                              "application/octet-stream",
                              "Accept-Ranges: bytes\r\n");
                        log("PUBLISHER immutable content download completed bytes=" +
                            std::to_string(content->size()));
                    }
                }
            }
            catch (const std::exception &)
            {
                reply(socket, 500, "{\"error\":\"publisher_content_unavailable\"}");
            }
        }
        else if (method == "GET" && path.starts_with("/platform/resources/"))
        {
            const auto content = platform_resources::download(path);
            if (!content)
                reply(socket, 404, "{\"error\":\"resource_not_found\"}");
            else
            {
                reply(socket, 200, *content, "application/octet-stream");
                log("PLATFORM resource content downloaded");
            }
        }
        else if (method == "POST" && path == "/platform/resource")
        {
            if (!hasLength || length != 48)
            {
                reply(socket, 400, "{\"error\":\"invalid_resource_request\"}");
                return;
            }
            try
            {
                reply(socket,
                      200,
                      platform::resource(request.substr(bodyAt, length)),
                      "application/octet-stream");
                log("PLATFORM signed BN/apft resource publication issued");
            }
            catch (const std::exception &)
            {
                reply(socket, 400, "{\"error\":\"resource_key_rejected\"}");
            }
        }
        else if (method == "POST" &&
                 (path == "/platform/login" || path.starts_with("/platform/login/")))
        {
            if (!hasLength || length != 32 || path == "/platform/login/")
            {
                reply(socket, 400, "{\"error\":\"invalid_platform_request\"}");
                return;
            }
            try
            {
                sockaddr_in peer{};
                int peerSize = sizeof(peer);
                const bool loopback =
                    getpeername(socket, reinterpret_cast<sockaddr *>(&peer), &peerSize) == 0 &&
                    peer.sin_family == AF_INET && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
                const auto profile = path == "/platform/login" ? "" : path.substr(16);
                if (!network::loginPermitted(loopback, profile, accessHeader.value_or("")))
                {
                    reply(socket, 403, "{\"error\":\"platform_access_rejected\"}");
                    return;
                }
                auto response = platform::login(request.substr(bodyAt, length), profile);
                reply(socket, 200, response, "application/octet-stream");
                log("PLATFORM issued signed local identity/session; native DW authentication still "
                    "required");
            }
            catch (const std::exception &)
            {
                reply(socket, 400, "{\"error\":\"platform_session_rejected\"}");
            }
        }
        else if (method == "POST" && path == "/auth/")
        {
            ++authRequests;
            try
            {
                auto response = platform::authenticate(request.substr(bodyAt, length));
                reply(socket,
                      200,
                      response.body,
                      "application/json",
                      "X-Signature: " + response.signature + "\r\n");
                log("AUTH signed native PC ticket issued; awaiting legacy login and encrypted "
                    "lobby");
            }
            catch (const std::runtime_error &error)
            {
                // authenticate() uses fixed, code-owned diagnostics here. Never
                // echo a parser exception, request body or credential values.
                reply(socket, 400, "{\"error\":\"native_auth_rejected\"}");
                log(std::string("AUTH rejected: ") + error.what());
            }
            catch (const std::exception &)
            {
                reply(socket, 400, "{\"error\":\"native_auth_rejected\"}");
                log("AUTH rejected: JSON parse/type/missing-field failure; request values omitted");
            }
        }
        else if (method == "POST" && path == "/v1.0/tokens/lsg/?client=replaylocal")
        {
            try
            {
                reply(socket, 200, platform::legacyLogin(request.substr(bodyAt, length)));
                log("LEGACY ticket-bound local account login accepted");
            }
            catch (const std::exception &)
            {
                reply(socket,
                      400,
                      "{\"error\":{\"code\":1,\"name\":\"invalid_ticket\",\"msg\":\"Local account "
                      "ticket rejected\"}}");
                log("LEGACY rejected invalid or expired ticket; credentials omitted");
            }
        }
        else
            reply(socket, 404, "{\"error\":\"unknown_route\"}");
    }

    void nativeAuth(SOCKET socket)
    {
        std::array<unsigned char, 5> prefix{};
        if (!receiveExact(socket, prefix.data(), static_cast<unsigned>(prefix.size())))
            return;
        if (prefix[0] == 0x16 && prefix[1] == 3)
        {
            // This is an explicit unsupported TLS endpoint, never an auth-success stub.
            ++authRequests;
            log("AUTH native TLS ClientHello received; local TLS trust/signing integration "
                "pending");
            const std::string alert("\x15\x03\x03\x00\x02\x02\x28", 7);
            sendAll(socket, alert);
        }
        else
            log("AUTH rejected non-TLS connection");
    }

    void lobbyConnection(SOCKET socket)
    {
        unsigned reads = 0;
        const DWORD timeout = 1000;
        setsockopt(socket,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   reinterpret_cast<const char *>(&timeout),
                   sizeof(timeout));
        lobby::serve({[socket, &reads](std::span<uint8_t> bytes)
                      {
                          const auto begin = std::chrono::steady_clock::now();
                          auto partial = begin;
                          size_t at = 0;
                          const auto idle = std::chrono::seconds(++reads < 5 ? 30 : 600);
                          while (at < bytes.size() && !stopping.load())
                          {
                              const int n = recv(socket,
                                                 reinterpret_cast<char *>(bytes.data() + at),
                                                 static_cast<int>(bytes.size() - at),
                                                 0);
                              if (n > 0)
                              {
                                  at += static_cast<size_t>(n);
                                  partial = std::chrono::steady_clock::now();
                                  continue;
                              }
                              if (!n || WSAGetLastError() != WSAETIMEDOUT)
                                  return false;
                              const auto now = std::chrono::steady_clock::now();
                              if (now - begin > idle ||
                                  (at && now - partial > std::chrono::seconds(10)))
                                  return false;
                          }
                          return at == bytes.size();
                      },
                      [socket](std::span<const uint8_t> bytes)
                      {
                          return sendAll(socket,
                                         std::string(reinterpret_cast<const char *>(bytes.data()),
                                                     bytes.size()));
                      },
                      log});
    }

    using Handler = void (*)(SOCKET);

    void listenOn(unsigned short port, Handler handler)
    {
        Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (listener.value == INVALID_SOCKET)
            throw std::runtime_error("socket creation failed");
        const BOOL exclusive = TRUE;
        setsockopt(listener.value,
                   SOL_SOCKET,
                   SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char *>(&exclusive),
                   sizeof(exclusive));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = network::bindAddress();
        address.sin_port = htons(port);
        if (bind(listener.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)) ||
            listen(listener.value, SOMAXCONN))
            throw std::runtime_error("cannot bind port " + std::to_string(port) + ": " +
                                     std::to_string(WSAGetLastError()));
        log("LISTEN port=" + std::to_string(port));
        while (!stopping.load())
        {
            fd_set readable{};
            FD_SET(listener.value, &readable);
            timeval timeout{0, 250000};
            const int ready = select(0, &readable, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR)
                break;
            if (!ready)
                continue;
            const SOCKET client = accept(listener.value, nullptr, nullptr);
            if (client == INVALID_SOCKET)
                continue;
            if (active.fetch_add(1) >= maxClients)
            {
                --active;
                closesocket(client);
                continue;
            }
            const DWORD milliseconds = 3000;
            setsockopt(client,
                       SOL_SOCKET,
                       SO_RCVTIMEO,
                       reinterpret_cast<const char *>(&milliseconds),
                       sizeof(milliseconds));
            setsockopt(client,
                       SOL_SOCKET,
                       SO_SNDTIMEO,
                       reinterpret_cast<const char *>(&milliseconds),
                       sizeof(milliseconds));
            try
            {
                std::thread(
                    [client, handler]
                    {
                        Socket connection(client);
                        try
                        {
                            sockaddr_in peer{};
                            int size = sizeof(peer);
                            if (getpeername(client, reinterpret_cast<sockaddr *>(&peer), &size) ||
                                peer.sin_family != AF_INET)
                                throw std::runtime_error("Cannot determine connection peer");
                            const network::PeerScope publication(peer.sin_addr.s_addr);
                            handler(client);
                        }
                        catch (const std::exception &e)
                        {
                            log(std::string("REQUEST error: ") + e.what());
                        }
                        --active;
                    })
                    .detach();
            }
            catch (...)
            {
                --active;
                closesocket(client);
                throw;
            }
        }
    }

    BOOL WINAPI control(DWORD)
    {
        stopping = true;
        return TRUE;
    }
} // namespace

int main(int argc, char **argv)
{
    std::filesystem::path directory = argc > 1 ? argv[1] : "data";
    if (argc == 4 && std::string(argv[2]) == "--inspect-relay-client-token")
    {
        try
        {
            relay::initialize(directory);
            const auto token = wire::base64(argv[3], 77);
            const auto claims = relay::verifyClientToken(token);
            std::printf("{\"valid\":true,\"title\":%u,\"user\":%llu,\"expires\":%u,\"active_"
                        "session_checked\":false,\"udp_transport_verified\":false}\n",
                        claims.title,
                        static_cast<unsigned long long>(claims.user),
                        claims.expires);
            return 0;
        }
        catch (...)
        {
            std::fprintf(stderr, "Relay client credential rejected\n");
            return 2;
        }
    }
    unsigned portOffset = 0;
    if (argc > 3 && std::string(argv[2]) == "--port-offset")
    {
        const std::string value = argv[3];
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), portOffset);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
            portOffset > 50000)
        {
            std::fprintf(stderr, "Invalid test port offset\n");
            return 1;
        }
    }
    std::filesystem::create_directories(directory);
    logFile.open(directory / "server.log", std::ios::app);
    if (!logFile)
    {
        std::fprintf(stderr, "Cannot open server log\n");
        return 1;
    }
    try
    {
        network::initialize(directory);
        platform::initialize(directory);
        if (argc == 5 && std::string(argv[2]) == "--provision-profile")
        {
            platform::provisionProfile(directory, argv[3], argv[4]);
            log("PLATFORM additional persistent local identity provisioned");
            return 0;
        }
        platform_resources::initialize(directory, static_cast<unsigned short>(8085 + portOffset));
        services::initialize(directory);
        services::initializePublisherContent(directory,
                                             static_cast<unsigned short>(8085 + portOffset));
        services::initializeContentStreaming(directory,
                                             static_cast<unsigned short>(8085 + portOffset));
        if (argc > 2 && std::string(argv[2]) == "--provision")
        {
            log("PLATFORM persistent identity and signing key provisioned");
            return 0;
        }
    }
    catch (const std::exception &e)
    {
        log(e.what());
        return 1;
    }
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa))
        return 1;
    try
    {
        qos_provider::start(directory);
        relay_provider::start(directory);
    }
    catch (const std::exception &e)
    {
        log(e.what());
        relay_provider::stop();
        qos_provider::stop();
        WSACleanup();
        return 1;
    }
    SetConsoleCtrlHandler(control, TRUE);
    log("START IW8 Replay120 external server; signed auth, legacy account login, protocol 210 "
        "lobby, profiles and storage");
    std::atomic<bool> failed{false};
    auto run = [&failed](unsigned short port, Handler handler)
    {
        try
        {
            listenOn(port, handler);
        }
        catch (const std::exception &e)
        {
            log(std::string("LISTENER error: ") + e.what());
            failed = true;
            stopping = true;
        }
    };
    std::thread auth(run, static_cast<unsigned short>(8443 + portOffset), nativeAuth),
        tasks(run, static_cast<unsigned short>(3075 + portOffset), lobbyConnection);
    run(static_cast<unsigned short>(8085 + portOffset), http);
    auth.join();
    tasks.join();
    while (active.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    relay_provider::stop();
    qos_provider::stop();
    WSACleanup();
    log("STOP");
    return failed.load() ? 1 : 0;
}
