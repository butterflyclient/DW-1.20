#include "tls_transport.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <stdexcept>
#include <chrono>
#include <memory>
#include <mutex>
#ifndef _WIN32
#include <openssl/ssl.h>
#include <poll.h>
#include <openssl/err.h>
#endif

namespace tls_transport
{
    namespace
    {
        bool configured = false, requireRemote = true;
        unsigned short httpsPort = 8443;
        bool allowLegacyPublicUpdates = false;
#ifndef _WIN32
        struct Context
        {
            SSL_CTX *value = nullptr;
            ~Context() { SSL_CTX_free(value); }
        } context;
        std::mutex contextMutex;
        std::filesystem::path certificatePath, keyPath;
        std::filesystem::file_time_type certificateTime{}, keyTime{};
        thread_local SSL *current = nullptr;
        thread_local SOCKET currentSocket = INVALID_SOCKET;

        bool waitFor(SOCKET socket, int error, Deadline deadline)
        {
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return false;
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0)
                return false;
            pollfd ready{socket, static_cast<short>(error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0};
            return poll(&ready, 1, static_cast<int>(remaining)) > 0;
        }

        void reloadCertificate()
        {
            const auto certificateStamp = std::filesystem::last_write_time(certificatePath);
            const auto keyStamp = std::filesystem::last_write_time(keyPath);
            if (context.value && certificateStamp == certificateTime && keyStamp == keyTime)
                return;
            std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> candidate(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
            auto *next = candidate.get();
            if (!next || SSL_CTX_set_min_proto_version(next, TLS1_2_VERSION) != 1 ||
                SSL_CTX_set_ciphersuites(next,
                    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384") != 1 ||
                SSL_CTX_set_cipher_list(next,
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384") != 1 ||
                SSL_CTX_use_certificate_chain_file(next, certificatePath.string().c_str()) != 1 ||
                SSL_CTX_use_PrivateKey_file(next, keyPath.string().c_str(), SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_check_private_key(next) != 1)
                throw std::runtime_error("TLS certificate/key or cipher configuration failed");
            SSL_CTX_set_options(next, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
            SSL_CTX_set_max_early_data(next, 0);
            SSL_CTX_set_session_cache_mode(next, SSL_SESS_CACHE_SERVER);
            static constexpr unsigned char sessionContext[] = "Replay DW HTTPS";
            if (SSL_CTX_set_session_id_context(next, sessionContext, sizeof(sessionContext) - 1) != 1)
                throw std::runtime_error("TLS session cache configuration failed");
            // SSL_new retains its context: existing connections survive renewal.
            SSL_CTX_free(context.value);
            context.value = candidate.release();
            certificateTime = certificateStamp;
            keyTime = keyStamp;
        }
#endif
    }

    void initialize(const std::filesystem::path &directory, unsigned offset)
    {
        const auto path = directory / "tls.json";
        if (!std::filesystem::exists(path))
            return;
#ifdef _WIN32
        (void)offset;
        throw std::runtime_error("TLS server configuration requires the Linux OpenSSL build");
#else
        std::ifstream input(path);
        const auto config = nlohmann::json::parse(input);
        if (config.at("schema") != 1)
            throw std::runtime_error("Unsupported TLS configuration schema");
        httpsPort = static_cast<unsigned short>(8443 + offset);
        requireRemote = config.value("require_remote_tls", true);
        allowLegacyPublicUpdates = config.value("allow_legacy_public_updates", false);
        certificatePath = directory / config.at("certificate_chain").get<std::string>();
        keyPath = directory / config.at("private_key").get<std::string>();
        reloadCertificate();
        configured = true;
#endif
    }

    bool enabled() { return configured; }
    bool required() { return requireRemote; }
    bool legacyUpdatesAllowed()
    {
        return configured && allowLegacyPublicUpdates;
    }
    unsigned short port() { return httpsPort; }
    bool active()
    {
#ifdef _WIN32
        return false;
#else
        return current != nullptr;
#endif
    }

    Connection::Connection(SOCKET socket)
    {
#ifdef _WIN32
        (void)socket;
        throw std::runtime_error("TLS server unavailable on this platform");
#else
        if (!configured || current)
            throw std::runtime_error("Invalid TLS connection context");
        SSL *ssl;
        {
            std::lock_guard lock(contextMutex);
            reloadCertificate();
            ssl = SSL_new(context.value);
        }
        if (!ssl)
            throw std::runtime_error("TLS session allocation failed");
        // Bound the entire handshake, including a peer trickling individual records.
        const int flags = fcntl(socket, F_GETFL, 0);
        bool accepted = false;
        std::string failure = "socket-setup";
        if (flags >= 0 && SSL_set_fd(ssl, socket) == 1 &&
            fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0)
        {
            // Leave room for certificate validation/network scheduling within the
            // client's ten-second request budget; still bound silent/trickling peers.
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(9);
            ERR_clear_error();
            while (std::chrono::steady_clock::now() < deadline)
            {
                errno = 0;
                const int result = SSL_accept(ssl);
                const int socketError = errno;
                if (result == 1) { accepted = true; break; }
                const int error = SSL_get_error(ssl, result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                {
                    failure = error == SSL_ERROR_ZERO_RETURN ||
                              (error == SSL_ERROR_SYSCALL && result == 0 && socketError == 0) ? "peer-closed" :
                              error == SSL_ERROR_SYSCALL ? "socket" : "openssl";
                    failure += " ssl_error=" + std::to_string(error);
                    if (error == SSL_ERROR_SYSCALL)
                        failure += " socket_error=" + std::to_string(socketError);
                    const auto reason = ERR_peek_last_error();
                    if (reason)
                        failure += " openssl_reason=" + std::to_string(ERR_GET_REASON(reason));
                    break;
                }
                if (!waitFor(socket, error, deadline))
                {
                    failure = std::chrono::steady_clock::now() >= deadline ? "deadline" : "socket-wait";
                    break;
                }
            }
            if (!accepted && std::chrono::steady_clock::now() >= deadline)
                failure = "deadline";
        }
        if (!accepted)
        {
            SSL_free(ssl);
            throw std::runtime_error("TLS handshake rejected: " + failure);
        }
        session = current = ssl;
        currentSocket = socket;
#endif
    }

    Connection::~Connection()
    {
#ifndef _WIN32
        if (session)
        {
            SSL_shutdown(static_cast<SSL *>(session));
            SSL_free(static_cast<SSL *>(session));
            current = nullptr;
            currentSocket = INVALID_SOCKET;
        }
#endif
    }

    int receive(SOCKET socket, char *data, int size, Deadline deadline)
    {
#ifndef _WIN32
        if (current)
        {
            if (socket != currentSocket)
                return -1;
            while (std::chrono::steady_clock::now() < deadline)
            {
                const int result = SSL_read(current, data, size);
                if (result > 0)
                    return result;
                if (!waitFor(socket, SSL_get_error(current, result), deadline))
                    break;
            }
            return -1;
        }
#else
        (void)deadline;
#endif
        return recv(socket, data, size, 0);
    }

    int send(SOCKET socket, const char *data, int size, Deadline deadline)
    {
#ifndef _WIN32
        if (current)
        {
            if (socket != currentSocket)
                return -1;
            while (std::chrono::steady_clock::now() < deadline)
            {
                const int result = SSL_write(current, data, size);
                if (result > 0)
                    return result;
                if (!waitFor(socket, SSL_get_error(current, result), deadline))
                    break;
            }
            return -1;
        }
#else
        (void)deadline;
#endif
        return ::send(socket, data, size, 0);
    }
}
