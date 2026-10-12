#pragma once
#include "sv_host_scale.h"
#include "replay_dvar.h"

namespace DWNoclip
{
    // Complete byte views through every consumed native field. The remaining
    // SvClientMP/gclient storage stays owned by the engine.
    struct ServerClient
    {
        const uintptr_t *vtable;
        uint8_t state;
        uint8_t opaque9[271];
        HostScale::Entity *entity;
    };
    struct PlayerClient
    {
        uint8_t opaque0[12];
        int32_t movementType;
        uint8_t opaque16[432];
        int32_t clientNumber;
        uint8_t opaque452[20916];
        int32_t connectionState, sessionState;
        uint8_t opaque21376[2640];
        uint32_t flags;
    };
    static_assert(sizeof(ServerClient) == 288 && offsetof(ServerClient, entity) == 280);
    static_assert(sizeof(PlayerClient) == 24020 && offsetof(PlayerClient, clientNumber) == 448);
    static_assert(offsetof(PlayerClient, connectionState) == 21368);
    static_assert(offsetof(PlayerClient, sessionState) == 21372);
    static_assert(offsetof(PlayerClient, flags) == 24016);
    constexpr uint32_t NoClip = 1;
}

extern "C" void DW_Noclip_ClientCommand(int clientNumber);
