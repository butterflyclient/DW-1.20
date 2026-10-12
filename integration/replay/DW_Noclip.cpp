#include "DW_Noclip.h"
#include "DW_NoclipBindings.h"

namespace
{
    bool Equal(const char *left, const char *right)
    {
        if (!left || !right)
            return false;
        while (*left && *right)
        {
            unsigned a = uint8_t(*left++), b = uint8_t(*right++);
            if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
            if (a != b) return false;
        }
        return *left == *right;
    }

    void Reply(DWNoclip::ServerClient *client, const char *text)
    {
        // Exact native SvClient::SendServerCommand ABI, proved by the complete
        // SV_Game_BroadcastServerCommand body. Send only to this requester.
        if (client->vtable && client->vtable[1])
            reinterpret_cast<void (*)(DWNoclip::ServerClient *, int, const char *)>(
                client->vtable[1])(client, 0, text);
    }
}

extern "C" bool DW_Noclip_StringCommand(DWNoclip::ServerClient *client, void *message,
                                         int sequence, bool fromOldServer)
{
    return NC_StringCommandNative(client, message, sequence, fromOldServer);
}

// The native reliable client-command path has already authenticated the sender,
// rejected old-server messages and established server GameStatics/TLS before
// calling this identity. All other commands retain its complete original body.
extern "C" void DW_Noclip_ClientCommand(int clientNumber)
{
    const char *command = NC_Argv(0);
    if (!Equal(command, "noclip") && !Equal(command, "mw_noclip"))
    {
        NC_ClientCommandNative(clientNumber);
        return;
    }
    if (!NC_ServerLoaded() || NC_ClientCount > 200 || clientNumber < 0 ||
        unsigned(clientNumber) >= NC_ClientCount || !NC_Entities)
        return;
    auto *client = NC_Clients[clientNumber];
    auto *entity = &NC_Entities[clientNumber];
    if (!client || client->state < 5 || client->entity != entity ||
        entity->number != clientNumber || !entity->client)
        return;
    auto *player = reinterpret_cast<DWNoclip::PlayerClient *>(entity->client);
    if (player->clientNumber != clientNumber || player->connectionState != 2 ||
        player->sessionState != 0 || entity->health <= 0)
    {
        Reply(client, "e \"Noclip requires a living player in the match.\"");
        return;
    }
    // The host is the server's authenticated local connection, never a local
    // frontend checkbox, party display name or client-supplied command field.
    const auto *cheats = NC_FindDvar("NTPNRQTKNP"); // Replay sv_cheats token.
    if (!NC_IsLocalClient(clientNumber) &&
        !(cheats && cheats->type == 0 && cheats->current.enabled))
    {
        Reply(client, "e \"Noclip requires the host or server sv_cheats 1.\"");
        return;
    }
    const char *argument = NC_Argv(1), *extra = NC_Argv(2);
    if (!argument || !extra)
        return;
    bool enabled = (player->flags & DWNoclip::NoClip) == 0;
    if (*argument)
    {
        if (Equal(argument, "1") || Equal(argument, "on")) enabled = true;
        else if (Equal(argument, "0") || Equal(argument, "off")) enabled = false;
        else
        {
            Reply(client, "e \"Usage: noclip [0|1|off|on]\"");
            return;
        }
    }
    if (*extra)
    {
        Reply(client, "e \"Usage: noclip [0|1|off|on]\"");
        return;
    }
    player->flags = enabled ? player->flags | DWNoclip::NoClip
                            : player->flags & ~DWNoclip::NoClip;
    // Native MP client movement consumes this flag and sets PM_NOCLIP. It
    // owns collision, velocity, replication and restoration of normal movement.
    Reply(client, enabled ? "e \"Noclip enabled.\"" : "e \"Noclip disabled.\"");
}
