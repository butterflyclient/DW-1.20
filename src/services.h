#pragma once
#include "platform.h"
#include "wire.h"
#include <filesystem>
#include <optional>

namespace services
{
    struct RESTResult
    {
        uint32_t version = 0, status = 503;
        std::string body;
    };

    struct Delivery
    {
        uint64_t user = 0;
        wire::Bytes payload;
        uint32_t delayMs = 0;
        uint64_t lobbyId = 0, searchId = 0;
        uint64_t presenceUser = 0, presenceRevision = 0;
        std::string presenceContext;
        uint64_t clanGroup = 0, clanUser = 0;
        uint32_t clanEvent = 0, clanRole = 0;
    };

    struct Reply
    {
        uint32_t error = 0;
        std::vector<wire::Bytes> results;
        std::string operation;
        bool structured = false;
        wire::Bytes structure;
        std::vector<wire::Bytes> pushes;
        std::optional<RESTResult> rest;
        std::string detail;
        std::vector<Delivery> deliveries;
    };

    void initialize(const std::filesystem::path &directory);
    std::vector<Delivery> disconnected(uint32_t title, uint64_t user);
    bool deliveryValid(uint32_t title, const Delivery &delivery);
    Reply dispatch(const platform::LobbyIdentity &identity,
                   uint8_t service,
                   uint8_t task,
                   wire::Reader &params);
    wire::Bytes taskReply(uint64_t transaction, uint8_t task, const Reply &reply);
} // namespace services
