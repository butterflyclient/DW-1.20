#include <windows.h>
#include <bcrypt.h>
#include "platform.h"
#include "platform_resources.h"
#include "crypto.h"
#include "../integration/replay/dw_platform_protocol.h"
#include <array>
#include <chrono>
#include <charconv>
#include <cstring>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <vector>
#include <map>
#include <set>
#include "../third_party/nlohmann/json.hpp"

namespace platform
{
    namespace
    {
        struct Identity
        {
            uint32_t magic = DW_LOCAL_PLATFORM_MAGIC;
            uint32_t version = 1;
            uint64_t userId = 0;
            uint32_t gameAccountId = 0;
            char name[36] = "DWPlayer";
        };

        static_assert(sizeof(Identity) == 56);

        struct Session
        {
            DWLocalPlatformPayload payload;
            std::array<uint8_t, 128> serverTicket{};
            std::array<uint8_t, 24> sessionKey{};
            uint32_t titleId = 0;
            uint32_t ivSeed = 0;
            std::string umbrellaToken;
        };

        Identity identity;
        std::map<std::string, Identity> profiles;
        std::filesystem::path identityDirectory;
        BCRYPT_ALG_HANDLE rsa = nullptr, sha = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        std::mutex mutex;
        std::vector<Session> issuedSessions;
        unsigned loginCount = 0;
        unsigned authCount = 0;
        unsigned legacyCount = 0;

        void check(NTSTATUS result, const char *operation)
        {
            if (result < 0)
                throw std::runtime_error(std::string("Platform crypto failure: ") + operation);
        }

        std::vector<unsigned char> read(const std::filesystem::path &path)
        {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file || file.tellg() <= 0 || file.tellg() > 16384)
                throw std::runtime_error("Invalid platform identity/key file");
            std::vector<unsigned char> bytes(static_cast<size_t>(file.tellg()));
            file.seekg(0);
            if (!file.read(reinterpret_cast<char *>(bytes.data()),
                           static_cast<std::streamsize>(bytes.size())))
                throw std::runtime_error("Cannot read platform identity/key file");
            return bytes;
        }

        void write(const std::filesystem::path &path, const void *data, size_t size)
        {
            auto pending = path;
            pending += ".creating";
            {
                std::ofstream file(pending, std::ios::binary | std::ios::trunc);
                if (!file.write(static_cast<const char *>(data),
                                static_cast<std::streamsize>(size)) ||
                    !file.flush())
                    throw std::runtime_error("Cannot persist platform identity/key");
            }
            if (!MoveFileExW(pending.c_str(), path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Cannot publish platform identity/key");
        }

        void profileKey(const std::string &value)
        {
            if (value.empty() || value.size() > 32)
                throw std::runtime_error("Invalid local profile key");
            for (const char c : value)
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
                    throw std::runtime_error("Invalid local profile key");
        }

        Identity readIdentity(const std::filesystem::path &path)
        {
            const auto bytes = read(path);
            Identity result;
            if (bytes.size() != sizeof(result))
                throw std::runtime_error("Platform identity layout mismatch");
            std::memcpy(&result, bytes.data(), sizeof(result));
            if (result.magic != DW_LOCAL_PLATFORM_MAGIC || result.version != 1 || !result.userId ||
                result.userId == UINT64_MAX || !result.gameAccountId || !result.name[0] ||
                result.name[35])
                throw std::runtime_error("Invalid persisted platform identity");
            const auto name = std::string(result.name);
            for (const unsigned char c : name)
                if (c < 32 || c >= 127)
                    throw std::runtime_error("Invalid local profile name");
            return result;
        }

        void validateName(const std::string &name)
        {
            if (name.empty() || name.size() >= 36 || name.front() == ' ' || name.back() == ' ')
                throw std::runtime_error("Invalid local profile name");
            for (const unsigned char c : name)
                if (c < 32 || c >= 127 || c == '#' || c == '%')
                    throw std::runtime_error("Invalid local profile name");
        }

        std::string folded(std::string value)
        {
            for (auto &c : value)
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c + ('a' - 'A'));
            return value;
        }

        void availableName(const std::string &name, uint64_t own = 0)
        {
            validateName(name);
            const auto match = folded(name);
            if (identity.userId != own && folded(identity.name) == match)
                throw std::runtime_error("Local player name already in use");
            for (const auto &[profile, other] : profiles)
                if (other.userId != own && folded(other.name) == match)
                    throw std::runtime_error("Local player name already in use");
        }

        Identity newIdentity(const std::string &name)
        {
            validateName(name);
            Identity result;
            check(BCryptGenRandom(nullptr,
                                  reinterpret_cast<unsigned char *>(&result.userId),
                                  sizeof(result.userId),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                  "identity random");
            result.userId = (result.userId & 0x00000000ffffffffULL) | 0x110000100000000ULL;
            result.gameAccountId = static_cast<uint32_t>(result.userId) | 1;
            std::memset(result.name, 0, sizeof(result.name));
            std::memcpy(result.name, name.data(), name.size());
            return result;
        }

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        void token(char (&text)[65])
        {
            unsigned char random[32]{};
            check(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                  "token random");
            constexpr char hex[] = "0123456789abcdef";
            for (unsigned i = 0; i < sizeof(random); ++i)
            {
                text[i * 2] = hex[random[i] >> 4];
                text[i * 2 + 1] = hex[random[i] & 15];
            }
            text[64] = 0;
            SecureZeroMemory(random, sizeof(random));
        }

        std::string base64(const void *source, size_t length)
        {
            constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            const auto *data = static_cast<const uint8_t *>(source);
            std::string out;
            for (size_t i = 0; i < length; i += 3)
            {
                unsigned v = static_cast<unsigned>(data[i]) << 16;
                if (i + 1 < length)
                    v |= static_cast<unsigned>(data[i + 1]) << 8;
                if (i + 2 < length)
                    v |= data[i + 2];
                out += alphabet[(v >> 18) & 63];
                out += alphabet[(v >> 12) & 63];
                out += i + 1 < length ? alphabet[(v >> 6) & 63] : '=';
                out += i + 2 < length ? alphabet[v & 63] : '=';
            }
            return out;
        }

        void sign(const void *bytes, size_t size, uint8_t (&signature)[256], unsigned saltBytes)
        {
            unsigned char digest[32]{};
            BCRYPT_HASH_HANDLE hash = nullptr;
            check(BCryptCreateHash(sha, &hash, nullptr, 0, nullptr, 0, 0), "payload hash creation");
            auto result = BCryptHashData(hash,
                                         static_cast<unsigned char *>(const_cast<void *>(bytes)),
                                         static_cast<unsigned long>(size),
                                         0);
            if (result >= 0)
                result = BCryptFinishHash(hash, digest, sizeof(digest), 0);
            BCryptDestroyHash(hash);
            check(result, "payload hash");
            BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, saltBytes};
            unsigned long written = 0;
            check(BCryptSignHash(key,
                                 &padding,
                                 digest,
                                 sizeof(digest),
                                 signature,
                                 sizeof(signature),
                                 &written,
                                 BCRYPT_PAD_PSS),
                  "payload signature");
            if (written != sizeof(signature))
                throw std::runtime_error("Signature length mismatch");
        }

        void exportKey(const std::filesystem::path &path, const wchar_t *format)
        {
            unsigned long count = 0;
            check(BCryptExportKey(key, nullptr, format, nullptr, 0, &count, 0),
                  "key export length");
            std::vector<unsigned char> blob(count);
            check(BCryptExportKey(key, nullptr, format, blob.data(), count, &count, 0),
                  "key export");
            write(path, blob.data(), count);
            SecureZeroMemory(blob.data(), blob.size());
        }
    } // namespace

    void initialize(const std::filesystem::path &directory)
    {
        identityDirectory = std::filesystem::absolute(directory);
        check(BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, nullptr, 0), "RSA provider");
        check(BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
              "SHA256 provider");
        const auto privatePath = directory / "platform-private.blob";
        const auto publicPath = directory / "platform-public.blob";
        if (std::filesystem::exists(privatePath))
        {
            auto blob = read(privatePath);
            check(BCryptImportKeyPair(rsa,
                                      nullptr,
                                      BCRYPT_RSAPRIVATE_BLOB,
                                      &key,
                                      blob.data(),
                                      static_cast<unsigned long>(blob.size()),
                                      0),
                  "RSA key import");
            SecureZeroMemory(blob.data(), blob.size());
            // Do not silently change the compiler's pinned key.
            auto publicBlob = read(publicPath);
            unsigned long length = 0;
            check(BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &length, 0),
                  "public export length");
            std::vector<unsigned char> actual(length);
            check(BCryptExportKey(
                      key, nullptr, BCRYPT_RSAPUBLIC_BLOB, actual.data(), length, &length, 0),
                  "public export");
            if (actual != publicBlob)
                throw std::runtime_error("Platform public/private key mismatch");
        }
        else
        {
            if (std::filesystem::exists(publicPath))
                throw std::runtime_error(
                    "Platform private key is missing; recover it before rebuilding trust");
            check(BCryptGenerateKeyPair(rsa, &key, 2048, 0), "RSA generation");
            check(BCryptFinalizeKeyPair(key, 0), "RSA finalization");
            exportKey(privatePath, BCRYPT_RSAPRIVATE_BLOB);
            exportKey(publicPath, BCRYPT_RSAPUBLIC_BLOB);
        }
        const auto profilePath = directory / "platform-profile.bin";
        if (std::filesystem::exists(profilePath))
        {
            identity = readIdentity(profilePath);
        }
        else
        {
            identity = newIdentity("DWPlayer");
            write(profilePath, &identity, sizeof(identity));
        }
        profiles.clear();
        std::set<uint64_t> users{identity.userId};
        std::set<uint32_t> accounts{identity.gameAccountId};
        const auto extras = directory / "platform-profiles";
        if (std::filesystem::exists(extras))
            for (const auto &entry : std::filesystem::directory_iterator(extras))
            {
                if (!entry.is_regular_file() || entry.path().extension() != L".bin")
                    continue;
                const auto name = entry.path().stem().string();
                profileKey(name);
                auto profile = readIdentity(entry.path());
                if (profiles.size() >= 63 || !users.insert(profile.userId).second ||
                    !accounts.insert(profile.gameAccountId).second)
                    throw std::runtime_error("Duplicate or excessive local profiles");
                profiles.emplace(name, profile);
            }
    }

    void provisionProfile(const std::filesystem::path &directory,
                          const std::string &profile,
                          const std::string &name)
    {
        profileKey(profile);
        std::lock_guard lock(mutex);
        const auto path = directory / "platform-profiles" / (profile + ".bin");
        if (std::filesystem::exists(path) || profiles.contains(profile) || profiles.size() >= 63)
            throw std::runtime_error("Local profile already exists or capacity reached");
        availableName(name);
        auto result = newIdentity(name);
        for (unsigned attempt = 0;; ++attempt)
        {
            bool duplicate =
                result.userId == identity.userId || result.gameAccountId == identity.gameAccountId;
            for (const auto &entry : profiles)
                duplicate = duplicate || entry.second.userId == result.userId ||
                            entry.second.gameAccountId == result.gameAccountId;
            if (!duplicate)
                break;
            if (attempt >= 16)
                throw std::runtime_error("Local identity generation failed");
            result = newIdentity(name);
        }
        std::filesystem::create_directories(path.parent_path());
        write(path, &result, sizeof(result));
        profiles.emplace(profile, result);
    }

    std::optional<std::string> accountName(uint64_t user)
    {
        std::lock_guard lock(mutex);
        if (user == identity.userId)
            return std::string(identity.name);
        for (const auto &entry : profiles)
            if (entry.second.userId == user)
                return std::string(entry.second.name);
        return std::nullopt;
    }

    std::vector<Account> findAccounts(const std::string &username, bool prefix)
    {
        std::lock_guard lock(mutex);
        std::vector<Account> found;
        const auto match = folded(username);
        const auto append = [&](const Identity &account)
        {
            const auto name = folded(account.name), tag = name + "#0";
            if (prefix ? (name.starts_with(match) || tag.starts_with(match))
                       : (name == match || tag == match))
                found.push_back({account.userId, account.name});
        };
        append(identity);
        for (const auto &[profile, account] : profiles)
            append(account);
        return found;
    }

    std::string login(const std::string &nonce, const std::string &profile,
                      const std::string &playerName)
    {
        if (nonce.size() != 32)
            throw std::runtime_error("Invalid platform nonce size");
        bool nonzero = false;
        for (auto c : nonce)
            nonzero |= c != 0;
        if (!nonzero)
            throw std::runtime_error("Invalid platform nonce");
        std::lock_guard lock(mutex);
        Identity *selected = &identity;
        if (!profile.empty())
        {
            profileKey(profile);
            const auto found = profiles.find(profile);
            if (found == profiles.end())
                throw std::runtime_error("Unknown local profile");
            selected = &found->second;
        }
        const auto time = now();
        std::erase_if(issuedSessions,
                      [time](const auto &session)
                      {
                          return session.payload.expires <= time;
                      });
        if (issuedSessions.size() >= 64)
            throw std::runtime_error("Platform session capacity reached");
        if (!playerName.empty() && playerName != selected->name)
        {
            availableName(playerName, selected->userId);
            auto renamed = *selected;
            std::memset(renamed.name, 0, sizeof(renamed.name));
            std::memcpy(renamed.name, playerName.data(), playerName.size());
            const auto path = profile.empty()
                                  ? identityDirectory / "platform-profile.bin"
                                  : identityDirectory / "platform-profiles" / (profile + ".bin");
            write(path, &renamed, sizeof(renamed));
            *selected = renamed;
        }
        DWLocalPlatformReply reply{};
        auto &p = reply.payload;
        p.magic = DW_LOCAL_PLATFORM_MAGIC;
        p.version = DW_LOCAL_PLATFORM_VERSION;
        std::memcpy(p.nonce, nonce.data(), sizeof(p.nonce));
        p.issued = time;
        p.expires = time + 3600;
        p.userId = selected->userId;
        p.gameAccountId = selected->gameAccountId;
        p.licenses = 1;
        p.region = 1;
        p.age = 21;
        p.accountPolicy = 0;
        p.capabilities = 1;
        std::memcpy(p.name, selected->name, sizeof(p.name));
        token(p.sessionToken);
        token(p.accountToken);
        sign(&p, sizeof(p), reply.signature, 32);
        issuedSessions.push_back({p});
        ++loginCount;
        return std::string(reinterpret_cast<const char *>(&reply), sizeof(reply));
    }

    unsigned sessions()
    {
        std::lock_guard lock(mutex);
        return static_cast<unsigned>(issuedSessions.size());
    }

    std::string resource(const std::string &bytes)
    {
        if (bytes.size() != sizeof(DWLocalResourceRequest))
            throw std::runtime_error("Invalid resource request size");
        DWLocalResourceRequest request{};
        std::memcpy(&request, bytes.data(), sizeof(request));
        bool nonzero = false;
        for (auto c : request.nonce)
            nonzero |= c != 0;
        if (!nonzero || request.program != 16974 || request.usage != 0x61706674 || request.locale ||
            request.region != 1)
            throw std::runtime_error("Unsupported resource key");
        std::lock_guard lock(mutex);
        DWLocalResourceReply reply{};
        auto &p = reply.payload;
        p.magic = DW_LOCAL_RESOURCE_MAGIC;
        p.version = 1;
        std::memcpy(p.nonce, request.nonce, sizeof(p.nonce));
        p.issued = now();
        p.expires = p.issued + 3600;
        p.program = request.program;
        p.usage = request.usage;
        p.locale = request.locale;
        p.region = request.region;
        const auto &handle = platform_resources::handle();
        const auto &content = platform_resources::content();
        if (handle.empty() || handle.size() > sizeof(p.handle) || content.empty() ||
            content.size() > sizeof(p.content))
            throw std::runtime_error("Resource unavailable");
        p.handleLength = static_cast<uint32_t>(handle.size());
        p.contentLength = static_cast<uint32_t>(content.size());
        std::memcpy(p.handle, handle.data(), handle.size());
        std::memcpy(p.content, content.data(), content.size());
        sign(&p, sizeof(p), reply.signature, 32);
        return std::string(reinterpret_cast<const char *>(&reply), sizeof(reply));
    }

    unsigned logins()
    {
        std::lock_guard lock(mutex);
        return loginCount;
    }

    unsigned authentications()
    {
        std::lock_guard lock(mutex);
        return authCount;
    }

    AuthReply authenticate(const std::string &request)
    {
        // Only the same-build Battle.net login task is supported here. Its native
        // request and reply IDs are 84/85. Other platform families require evidence.
        using Json = nlohmann::json;
        auto input = Json::parse(request);
        const auto number = [&input](const char *name) -> uint64_t
        {
            const auto &value = input.at(name);
            if (value.is_number_unsigned())
                return value.get<uint64_t>();
            if (value.is_number_integer() && value.get<int64_t>() >= 0)
                return static_cast<uint64_t>(value.get<int64_t>());
            if (value.is_string())
            {
                const auto &text = value.get_ref<const std::string &>();
                uint64_t result = 0;
                const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
                if (!text.empty() && parsed.ec == std::errc{} &&
                    parsed.ptr == text.data() + text.size())
                    return result;
            }
            throw std::runtime_error("Invalid unsigned authentication field");
        };
        if (!input.is_object() || number("auth_task") != 84 || number("iv_seed") > 0xffffffffULL)
            throw std::runtime_error("Unsupported native authentication request");
        const auto title = number("title_id");
        if (!title || title > 0xffffffffULL)
            throw std::runtime_error("Invalid title ID");
        auto extra = Json::parse(input.at("extra_data").get<std::string>());
        auto sessionToken = extra.at("session_token").get<std::string>();
        auto accountToken = extra.at("account_token").get<std::string>();
        if (sessionToken.size() != 64 || accountToken.size() != 64)
            throw std::runtime_error("Invalid platform credential size");
        std::lock_guard lock(mutex);
        Session *session = nullptr;
        const auto time = now();
        for (auto &candidate : issuedSessions)
        {
            unsigned difference = 0;
            for (unsigned i = 0; i < 64; ++i)
            {
                difference |= static_cast<uint8_t>(sessionToken[i]) ^
                              static_cast<uint8_t>(candidate.payload.sessionToken[i]);
                difference |= static_cast<uint8_t>(accountToken[i]) ^
                              static_cast<uint8_t>(candidate.payload.accountToken[i]);
            }
            if (!difference && candidate.payload.expires > time)
            {
                session = &candidate;
                break;
            }
        }
        if (!session)
            throw std::runtime_error("Platform credential pair unknown or expired");
        check(BCryptGenRandom(nullptr,
                              session->sessionKey.data(),
                              static_cast<unsigned long>(session->sessionKey.size()),
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG),
              "DW session key random");
        check(BCryptGenRandom(nullptr,
                              session->serverTicket.data(),
                              static_cast<unsigned long>(session->serverTicket.size()),
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG),
              "DW server ticket random");
        session->titleId = static_cast<uint32_t>(title);
        session->ivSeed = static_cast<uint32_t>(number("iv_seed"));
        session->umbrellaToken.clear();
        // Exact packed 128-byte PC auth ticket, proven by Replay's deserialize and
        // processAuthInfo. The native parser validates the signed reply and magic.
        std::array<uint8_t, 128> ticket{};
        const uint32_t magic = 0xefbdaddeU;
        const uint32_t issued = static_cast<uint32_t>(time),
                       expires = static_cast<uint32_t>(session->payload.expires);
        const uint64_t license = 51636;
        std::memcpy(ticket.data(), &magic, 4);
        ticket[4] = 0;
        std::memcpy(ticket.data() + 5, &session->titleId, 4);
        std::memcpy(ticket.data() + 9, &issued, 4);
        std::memcpy(ticket.data() + 13, &expires, 4);
        std::memcpy(ticket.data() + 17, &license, 8);
        std::memcpy(ticket.data() + 25, &session->payload.userId, 8);
        std::memcpy(ticket.data() + 33, session->payload.name, sizeof(session->payload.name));
        std::memcpy(ticket.data() + 97, session->sessionKey.data(), session->sessionKey.size());
        Json output = {
            {"auth_task", 85},
            {"code", 700},
            {"iv_seed", number("iv_seed")},
            {"loginqueue_enabled", false},
            {"crossplay_enabled", false},
            {"client_id", "replaylocal"},
            {"account_type", "bnet"},
            {"service_level", "paid"},
            {"client_ticket", base64(ticket.data(), ticket.size())},
            {"server_ticket", base64(session->serverTicket.data(), session->serverTicket.size())},
            {"identity", "356c4bc3"},
            {"extra_data", Json{{"extended_data", "replay-local-platform-v1"}}.dump()}};
        AuthReply reply;
        reply.body = output.dump();
        uint8_t signature[256]{};
        // Replay calls rsa_verify_hash_ex with PSS and salt length zero. Keep its
        // actual verifier unchanged; the local public key alone is selected in C++.
        sign(reply.body.data(), reply.body.size(), signature, 0);
        reply.signature = base64(signature, sizeof(signature));
        ++authCount;
        return reply;
    }

    bool authorize(std::span<const uint8_t> ticket,
                   uint32_t title,
                   uint32_t seed,
                   LobbyIdentity &result)
    {
        if (ticket.size() != 128)
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
        {
            if (session.titleId == title && session.ivSeed == seed &&
                session.payload.expires > now() && crypto::equal(ticket, session.serverTicket))
            {
                result.key = session.sessionKey;
                result.userId = session.payload.userId;
                result.expires = session.payload.expires;
                result.titleId = title;
                result.ivSeed = seed;
                result.platformAccountId = session.payload.gameAccountId;
                result.name = session.payload.name;
                return true;
            }
        }
        return false;
    }

    bool valid(const LobbyIdentity &sessionIdentity)
    {
        if (sessionIdentity.expires <= now())
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
            if (session.payload.expires > now() &&
                session.payload.userId == sessionIdentity.userId &&
                session.titleId == sessionIdentity.titleId &&
                session.ivSeed == sessionIdentity.ivSeed &&
                crypto::equal(session.sessionKey, sessionIdentity.key))
                return true;
        return false;
    }

    bool relaySessionMatches(uint32_t title, uint64_t user, std::span<const uint8_t> digest)
    {
        if (digest.size() != 8)
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
            if (session.titleId == title && session.payload.userId == user &&
                session.payload.expires > now())
            {
                const auto hash = crypto::sha256(session.sessionKey);
                if (crypto::equal(std::span(hash).first(8), digest))
                    return true;
            }
        return false;
    }

    unsigned legacyLogins()
    {
        std::lock_guard lock(mutex);
        return legacyCount;
    }

    bool sessionTokenMatches(const LobbyIdentity &sessionIdentity, const std::string &text)
    {
        if (text.size() != 64)
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
            if (session.payload.expires > now() && session.titleId == sessionIdentity.titleId &&
                session.payload.userId == sessionIdentity.userId &&
                crypto::equal(session.sessionKey, sessionIdentity.key) &&
                crypto::equal(
                    std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size()),
                    std::span(reinterpret_cast<const uint8_t *>(session.payload.sessionToken),
                              size_t(64))))
                return true;
        return false;
    }

    std::string legacyLogin(const std::string &request)
    {
        using Json = nlohmann::json;
        const auto input = Json::parse(request);
        const auto ticket = input.at("ticket").get<std::string>();
        const auto vector = input.at("initialVectorSeed").get<std::string>();
        const auto title = input.at("titleID").get<uint32_t>();
        std::lock_guard lock(mutex);
        for (auto &session : issuedSessions)
        {
            const auto seed = std::to_string(session.ivSeed);
            const auto expected = base64(session.serverTicket.data(), session.serverTicket.size());
            const auto expectedVector = base64(seed.data(), seed.size());
            if (!session.titleId || session.titleId != title || session.payload.expires <= now() ||
                !crypto::equal(
                    std::span(reinterpret_cast<const uint8_t *>(ticket.data()), ticket.size()),
                    std::span(reinterpret_cast<const uint8_t *>(expected.data()),
                              expected.size())) ||
                vector != expectedVector)
                continue;
            if (session.umbrellaToken.empty())
            {
                char text[65]{};
                token(text);
                session.umbrellaToken = text;
                SecureZeroMemory(text, sizeof(text));
            }
            ++legacyCount;
            // bdUmbrellaAccessInfo::deserializeFromJSON reads these three fields.
            // No UnoID is assigned: the native legacy account flow remains selected.
            return Json{{"accessToken", session.umbrellaToken},
                        {"expires", session.payload.expires},
                        {"umbrellaID", session.payload.userId}}
                .dump();
        }
        throw std::runtime_error("Legacy login ticket is unknown, expired or mismatched");
    }
} // namespace platform
